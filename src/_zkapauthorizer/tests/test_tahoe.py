"""
Tests for ``_zkapauthorizer.tahoe``.
"""

from io import BytesIO

from allmydata.client import config_from_string
from allmydata.test.strategies import write_capabilities
from fixtures import TempDir
from hyperlink import DecodedURL
from hypothesis import assume, given
from hypothesis.strategies import integers, just, lists, sampled_from, text, tuples
from pyutil.mathutil import div_ceil
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

from ..storage_common import required_passes
from ..tahoe import (
    CapStr,
    MemoryGrid,
    NotADirectoryError,
    NotWriteableError,
    ShareEncoding,
    Tahoe,
    TahoeAPIError,
    _scrub_cap,
    async_retry,
    attenuate_writecap,
    required_passes_for_data,
)
from .fixtures import Treq
from .resources import client_manager
from .strategies import encoding_parameters, minimal_tahoe_configs


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
        port=integers(min_value=1, max_value=2**16 - 1),
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
            self.fail(f"Expected TahoeAPIError, got {result!r}")  # pragma: nocover


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
    def test_list_directory(self):
        """
        ``make_directory`` creates a directory the children of which can be listed
        using ``list_directory``.
        """
        tahoe = self.get_client()
        dir_cap = yield Deferred.fromCoroutine(tahoe.make_directory())
        entry_names = list(map(str, range(5)))

        def file_content(name: str) -> bytes:
            return b"x" * (int(name) + 1)

        async def upload(name: str) -> tuple[str, CapStr]:
            cap = await tahoe.upload(lambda: BytesIO(file_content(name)))
            await tahoe.link(dir_cap, name, cap)
            return (name, cap)

        # Populate it a little
        expected_entry_caps = dict(
            (
                yield gatherResults(
                    [Deferred.fromCoroutine(upload(n)) for n in entry_names]
                )
            )
        )
        # Put another directory in it too.
        inner_dir_cap = yield Deferred.fromCoroutine(tahoe.make_directory())
        yield Deferred.fromCoroutine(tahoe.link(dir_cap, "directory", inner_dir_cap))

        # Read it back
        children = yield Deferred.fromCoroutine(tahoe.list_directory(dir_cap))

        self.expectThat(set(children), Equals({"directory"} | set(entry_names)))
        for name in entry_names:
            kind, details = children[name]
            self.expectThat(
                kind,
                Equals("filenode"),
            )
            self.expectThat(
                details["size"],
                Equals(len(file_content(name))),
                f"child {name} has unexpected size",
            )
            self.expectThat(
                details["ro_uri"],
                Equals(expected_entry_caps[name]),
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
            self.fail(f"expected ValueError, got {result!r}")  # pragma: nocover

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
            )  # pragma: nocover

    @inlineCallbacks
    def test_unlink(self):
        """
        ``unlink`` removes an entry from a directory.
        """
        content = b"some content"
        tahoe = self.get_client()

        # create a directory and put one entry in it
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

        # ensure the file is in the directory
        entries_before = yield Deferred.fromCoroutine(tahoe.list_directory(dir_cap))
        self.assertThat(list(entries_before.keys()), Equals([entry_name]))

        # unlink the file, leaving the directory empty again
        yield Deferred.fromCoroutine(tahoe.unlink(dir_cap, entry_name))
        entries_after = yield Deferred.fromCoroutine(tahoe.list_directory(dir_cap))
        self.assertThat(list(entries_after.keys()), Equals([]))

    @inlineCallbacks
    def test_unlink_readonly(self):
        """
        ``unlink`` fails to remove an entry from a read-only directory.
        """
        content = b"some content"
        tahoe = self.get_client()

        # create a directory and put one entry in it
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

        # ensure the file is in the directory
        entries_before = yield Deferred.fromCoroutine(tahoe.list_directory(dir_cap))
        self.assertThat(list(entries_before.keys()), Equals([entry_name]))

        # try to unlink the file but pass only the read-only cap so we
        # expect failure
        ro_dir_cap = attenuate_writecap(dir_cap)

        try:
            result = yield Deferred.fromCoroutine(tahoe.unlink(ro_dir_cap, entry_name))
        except NotWriteableError:
            pass
        else:
            self.fail(
                f"Expected link to fail with NotWriteableError, got {result!r} instead"
            )  # pragma: nocover

    @inlineCallbacks
    def test_unlink_non_directory(self):
        """
        ``unlink`` fails to remove an entry from "directory capability"
        that isn't actually a directory
        """
        content = b"some content"
        tahoe = self.get_client()

        # create a non-directory
        content = b"some content"
        non_dir_cap = yield Deferred.fromCoroutine(
            tahoe.upload(lambda: BytesIO(content))
        )

        # try to unlink some file from the non-directory (expecting
        # failure)
        try:
            result = yield Deferred.fromCoroutine(tahoe.unlink(non_dir_cap, "foo"))
        except (NotADirectoryError, NotWriteableError):
            # The real implementation and the memory implementation differ in
            # their behavior. :/ We need a create-mutable-non-directory API to
            # be able to write a test that hits `NotADirectoryError` for both
            # of them.
            pass
        else:
            self.fail(
                f"Expected link to fail with NotADirectoryError or NotWriteableError, got {result!r} instead"
            )  # pragma: nocover


class DirectoryIntegrationTests(IntegrationMixin, DirectoryTestsMixin, TestCase):
    """
    Integration tests for directory-related functionality.
    """


class DirectoryMemoryTests(MemoryMixin, DirectoryTestsMixin, TestCase):
    """
    In-memory tests for directory-related functionality.
    """


class ConfigTests(TestCase):
    """
    Tests for configuration-related behavior of ``Tahoe``.
    """

    @given(
        encoding_parameters().flatmap(
            lambda encoding: minimal_tahoe_configs(shares=just(encoding)).map(
                lambda config_text: (encoding, config_text),
            ),
        )
    )
    def test_get_config(self, params: tuple[tuple[int, int, int], str]) -> None:
        """
        ``Tahoe.get_config`` returns a ``TahoeConfig`` with an ``encoding`` that
        matches the encoding information in the configuration file.
        """
        (needed, _, total), config_text = params
        config = config_from_string("", "", config_text)
        client = Tahoe(None, config)
        self.assertThat(
            client.get_config().encoding,
            Equals(ShareEncoding(needed, total)),
        )


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


class RequiredPassesForDataTests(TestCase):
    """
    Tests for ``required_passes_for_data``.
    """

    @given(
        needed=integers(min_value=1, max_value=255),
        extra=integers(min_value=0, max_value=254),
        ciphertext_length=integers(min_value=1, max_value=2**20),
        bytes_per_pass=integers(min_value=1),
    )
    def test_required_passes_for_data(
        self, needed, extra, ciphertext_length, bytes_per_pass
    ) -> None:
        """
        ``required_passes_for_data`` computes a price based on the share sizes FEC
        produces for the given encoding parameters.
        """
        total = needed + extra
        assume(total <= 255)
        encoding = ShareEncoding(needed, total)

        # I wanted to use zfec to compute all of this stuff but it turns out
        # zfec doesn't actually do this part - Tahoe-LAFS does, and in a way
        # that we can't re-use without dragging in the whole immutable
        # publisher.  So, I hope I got this right.
        inshare_length = div_ceil(ciphertext_length, encoding.needed)
        expected = required_passes(bytes_per_pass, [inshare_length] * encoding.total)

        actual = required_passes_for_data(bytes_per_pass, encoding, ciphertext_length)
        self.assertThat(actual, Equals(expected))
