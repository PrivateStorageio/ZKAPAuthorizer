"""
Tests for ``_zkapauthorizer.tahoe``.
"""

from io import BytesIO

from allmydata.test.strategies import write_capabilities
from fixtures import TempDir
from hyperlink import DecodedURL
from hypothesis import given
from hypothesis.strategies import integers, lists, sampled_from, text, tuples
from testresources import setUpResources, tearDownResources
from testtools import TestCase
from testtools.matchers import (
    AfterPreprocessing,
    Contains,
    ContainsDict,
    Equals,
    Is,
    IsInstance,
    Not,
)
from testtools.twistedsupport import AsynchronousDeferredRunTest, failed, succeeded
from twisted.internet.defer import Deferred, gatherResults, inlineCallbacks
from twisted.python.filepath import FilePath

from ..tahoe import (
    MemoryGrid,
    NotWriteableError,
    Tahoe,
    TahoeAPIError,
    _scrub_cap,
    async_retry,
    attenuate_writecap,
)
from .fixtures import Treq
from .resources import client_manager


class IntegrationMixin:
    """
    Mixin for integration tests for ``Tahoe`` against a real Tahoe-LAFS client
    node.
    """

    # Get a Tahoe-LAFS client node connected to a storage node.
    resources = [("client", client_manager)]

    def setUp(self):
        super().setUp()
        setUpResources(self, self.resources, None)
        self.addCleanup(lambda: tearDownResources(self, self.resources, None))

    def get_client(self):
        """
        Create a new ``Tahoe`` instance talking to the Tahoe client node managed
        by our ``client`` resource manager.
        """
        # AsynchronousDeferredRunTest sets reactor on us.
        httpclient = self.useFixture(Treq(self.reactor, case=self)).client()
        return Tahoe(httpclient, self.client.read_config())


class MemoryMixin:
    """
    Mixin for tests for the in-memory Tahoe client API test double provided by
    ``MemoryGrid``.
    """

    def setUp(self):
        super().setUp()
        self.grid = MemoryGrid()

    def get_client(self):
        """
        Create a new Tahoe client object pointed at the ``MemoryGrid`` created in
        set up.
        """
        return self.grid.client()


class TahoeAPIErrorTests(TestCase):
    """
    Tests for ``TahoeAPIError``.
    """

    @given(cap=write_capabilities().map(lambda uri: uri.to_string().decode("ascii")))
    def test_scrub_cap(self, cap):
        """
        ``_scrub_cap`` returns a different string than it is called with.
        """
        self.assertThat(
            _scrub_cap(cap),
            Not(Equals(cap)),
        )

    @given(
        scheme=sampled_from(["http", "https"]),
        host=sampled_from(["127.0.0.1", "localhost", "example.invalid"]),
        port=integers(min_value=1, max_value=2 ** 16 - 1),
        query=lists(tuples(text(), text())),
        path_extra=lists(text()),
        cap=write_capabilities().map(lambda uri: uri.to_string().decode("ascii")),
    )
    def test_scrubbed_url(self, scheme, host, port, query, path_extra, cap):
        """
        ``TahoeAPIError.url`` has capability strings scrubbed from it to avoid
        accidentally leaking secrets in logs.
        """
        original_path = ("uri", cap) + tuple(path_extra)
        original = DecodedURL().replace(
            scheme=scheme, host=host, port=port, path=original_path, query=query
        )
        expected_path = ("uri", _scrub_cap(cap)) + tuple(path_extra)
        expected = original.replace(path=expected_path)

        original_exc = TahoeAPIError("get", original, 200, "")
        expected_exc = TahoeAPIError("get", expected, 200, "")
        self.assertThat(original_exc, Equals(expected_exc))


class UploadDownloadTestsMixin:
    """
    A mixin defining tests for ``upload`` and ``download``.
    """

    # Support test methods that return a Deferred.
    run_tests_with = AsynchronousDeferredRunTest.make_factory(timeout=60.0)

    @inlineCallbacks
    def test_found(self):
        """
        If the identified object can be downloaded then it is written to the given
        path.
        """
        client = self.get_client()

        workdir = FilePath(self.useFixture(TempDir()).join("test_found"))
        workdir.makedirs()
        content = b"abc" * 1024
        outpath = workdir.child("downloaded")

        cap = yield Deferred.fromCoroutine(client.upload(lambda: BytesIO(content)))
        yield Deferred.fromCoroutine(client.download(outpath, cap, None))

        self.assertThat(
            outpath.getContent(),
            Equals(content),
        )

    @inlineCallbacks
    def test_not_directory(self):
        """
        If a child path is given and the identified object is not a directory then ...
        """
        client = self.get_client()

        workdir = FilePath(self.useFixture(TempDir()).join("test_found"))
        workdir.makedirs()
        content = b"abc" * 1024
        outpath = workdir.child("downloaded")

        def get_content():
            return BytesIO(content)

        cap = yield Deferred.fromCoroutine(client.upload(get_content))

        d = Deferred.fromCoroutine(client.download(outpath, cap, ["somepath"]))
        try:
            result = yield d
        except TahoeAPIError as e:
            self.assertThat(e.method, Equals("get"))
            self.assertThat(e.status, Equals(400))
            self.assertThat(
                e.body,
                Contains("Files have no children named"),
            )
        else:
            self.fail(f"Expected TahoeAPIError, got {result!r}")


class UploadDownloadIntegrationTests(
    IntegrationMixin, UploadDownloadTestsMixin, TestCase
):
    """
    Integration tests for ``Tahoe`` against a real Tahoe-LAFS client node.
    """


class UploadDownloadMemoryTests(MemoryMixin, UploadDownloadTestsMixin, TestCase):
    """
    In-memory tests for ``Tahoe`` against a real Tahoe-LAFS client node.
    """


class DirectoryTestsMixin:
    """
    A mixin defining tests for directory-related functionality.

    Mix this in to a ``TestCase`` and supply a ``get_client`` method that
    returns a Tahoe client object.
    """

    # Support test methods that return a Deferred.
    run_tests_with = AsynchronousDeferredRunTest.make_factory(timeout=60.0)

    @inlineCallbacks
    def test_make_directory(self):
        """
        ``make_directory`` returns a coroutine that completes with the capability
        of a new, empty directory.
        """
        tahoe = self.get_client()

        dir_cap = yield Deferred.fromCoroutine(tahoe.make_directory())

        # If we can download it, consider that success.
        outpath = FilePath(self.useFixture(TempDir()).join("dir_contents"))
        yield Deferred.fromCoroutine(tahoe.download(outpath, dir_cap, None))
        self.assertThat(outpath.getContent(), Not(Equals(b"")))

    @inlineCallbacks
    def test_list_directory(self):
        """
        ``list_directory`` returns a coroutine that completes with a list of
        direct child entries in the given directory.
        """
        tahoe = self.get_client()

        dir_cap = yield Deferred.fromCoroutine(tahoe.make_directory())

        inpath = FilePath(self.useFixture(TempDir()).join("list_directory"))
        inpath.makedirs()

        entry_names = range(5)

        def file_content(n):
            return b"x" * (n + 1)

        async def upload(n):
            cap = await tahoe.upload(lambda: BytesIO(file_content(n)))
            await tahoe.link(dir_cap, str(n), cap)

        # Populate it a little
        yield gatherResults([Deferred.fromCoroutine(upload(n)) for n in entry_names])

        # Put another directory in it too.
        inner_dir_cap = yield Deferred.fromCoroutine(tahoe.make_directory())
        yield Deferred.fromCoroutine(tahoe.link(dir_cap, "directory", inner_dir_cap))

        # Read it back
        children = yield Deferred.fromCoroutine(tahoe.list_directory(dir_cap))

        self.expectThat(
            set(children), Equals({"directory"} | set(map(str, entry_names)))
        )
        for name in entry_names:
            kind, details = children[str(name)]
            self.expectThat(
                kind,
                Equals("filenode"),
            )
            self.expectThat(
                details["size"],
                Equals(len(file_content(name))),
                f"child {name} has unexpected size",
            )

        kind, details = children["directory"]
        self.expectThat(kind, Equals("dirnode"))
        self.expectThat(
            details,
            ContainsDict(
                {
                    "rw_uri": Equals(inner_dir_cap),
                }
            ),
        )

    @inlineCallbacks
    def test_list_not_a_directory(self):
        """
        ``list_directory`` returns a coroutine that raises ``ValueError`` when
        called with a capability that is not a directory capability.
        """
        tahoe = self.get_client()

        # Upload not-a-directory
        filecap = yield Deferred.fromCoroutine(
            tahoe.upload(lambda: BytesIO(b"hello world"))
        )

        d = Deferred.fromCoroutine(tahoe.list_directory(filecap))
        try:
            result = yield d
        except ValueError:
            pass
        else:
            self.fail(f"expected ValueError, got {result!r}")

    @inlineCallbacks
    def test_link(self):
        """
        ``link`` adds an entry to a directory.
        """
        tmp = FilePath(self.useFixture(TempDir()).path)
        content = b"some content"
        tahoe = self.get_client()

        dir_cap = yield Deferred.fromCoroutine(tahoe.make_directory())
        entry_name = "foo"
        entry_cap = yield Deferred.fromCoroutine(tahoe.upload(lambda: BytesIO(content)))
        yield Deferred.fromCoroutine(
            tahoe.link(
                dir_cap,
                entry_name,
                entry_cap,
            ),
        )

        outpath = tmp.child("destination")
        yield Deferred.fromCoroutine(
            tahoe.download(
                outpath,
                dir_cap,
                child_path=[entry_name],
            ),
        )

        self.assertThat(
            outpath.getContent(),
            Equals(content),
        )

    @inlineCallbacks
    def test_link_readonly(self):
        """
        If ``link`` is passed a read-only directory capability then it returns a
        coroutine that raises ``NotWriteableError``.
        """
        tahoe = self.get_client()
        dir_cap = yield Deferred.fromCoroutine(tahoe.make_directory())
        ro_dir_cap = attenuate_writecap(dir_cap)

        d = Deferred.fromCoroutine(tahoe.link(ro_dir_cap, "self", dir_cap))
        try:
            result = yield d
        except NotWriteableError:
            pass
        else:
            self.fail(
                f"Expected link to fail with NotWriteableError, got {result!r} instead"
            )


class DirectoryIntegrationTests(IntegrationMixin, DirectoryTestsMixin, TestCase):
    """
    Integration tests for directory-related functionality.
    """


class DirectoryMemoryTests(MemoryMixin, DirectoryTestsMixin, TestCase):
    """
    In-memory tests for directory-related functionality.
    """


class AsyncRetryTests(TestCase):
    """
    Tests for ``async_retry``.
    """

    def test_success(self):
        """
        If the decorated function returns a coroutine that returns a value then
        the coroutine returned by the decorator function returns the same
        value.
        """
        result = object()

        @async_retry([lambda exc: True])
        async def decorated():
            return result

        self.assertThat(
            Deferred.fromCoroutine(decorated()),
            succeeded(Is(result)),
        )

    def test_not_matched_failure(self):
        """
        If the decorated function returns a coroutine that raises an exception not
        matched by any of the matchers then the coroutine returned by the
        decorator function raises the same exception.
        """

        class Exc(Exception):
            pass

        @async_retry([lambda exc: False])
        async def decorated():
            raise Exc()

        self.assertThat(
            Deferred.fromCoroutine(decorated()),
            failed(
                AfterPreprocessing(
                    lambda f: f.value,
                    IsInstance(Exc),
                )
            ),
        )

    def test_matched_failure(self):
        """
        If the decorated function returns a coroutine that raises an exception
        that is matched by one of the matchers then function is called again
        and the same logic applied to its result.
        """

        fail = True
        result = object()

        @async_retry([lambda exc: True])
        async def decorated():
            nonlocal fail
            if fail:
                fail = False
                raise Exception()
            return result

        self.assertThat(
            Deferred.fromCoroutine(decorated()),
            succeeded(Is(result)),
        )
