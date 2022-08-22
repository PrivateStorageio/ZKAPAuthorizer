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
from tahoe_capabilities import readable_from_string, writeable_directory_from_string
from testresources import setUpResources, tearDownResources
from testtools import TestCase
from testtools.matchers import AfterPreprocessing, Equals, Is, IsInstance, Not
from testtools.twistedsupport import AsynchronousDeferredRunTest, failed, succeeded
from twisted.internet.defer import Deferred, gatherResults
from twisted.python.filepath import FilePath

from .._types import CapStr
from ..storage_common import required_passes
from ..tahoe import (
    DirectoryNode,
    FileNode,
    ITahoeClient,
    MemoryGrid,
    NotADirectoryError,
    NotWriteableError,
    ShareEncoding,
    Tahoe,
    TahoeAPIError,
    _scrub_cap,
    async_retry,
    attenuate_writecap,
    download_child,
    required_passes_for_data,
)
from .common import async_test, from_awaitable
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

    def setUp(self: TestCase) -> None:
        super().setUp()  # type: ignore[misc]
        setUpResources(self, self.resources, None)
        self.addCleanup(lambda: tearDownResources(self, self.resources, None))

    def get_client(self: TestCase) -> Tahoe:
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

    def setUp(self) -> None:
        super().setUp()  # type: ignore[misc]
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

    def get_client(self) -> ITahoeClient:
        """
        Get the ``ITahoeClient`` provider to test.
        """
        raise NotImplementedError()

    @async_test
    async def test_found(self) -> None:
        """
        If the identified object can be downloaded then it is written to the given
        path.
        """
        client = self.get_client()

        tempdir = self.useFixture(TempDir())  # type: ignore[attr-defined]
        workdir = FilePath(tempdir.join("test_found"))
        workdir.makedirs()
        content = b"abc" * 1024
        outpath = workdir.child("downloaded")

        cap = readable_from_string(await client.upload(lambda: BytesIO(content)))
        await client.download(outpath, cap)

        self.assertThat(  # type: ignore[attr-defined]
            outpath.getContent(),
            Equals(content),
        )


class DownloadChildTests(MemoryMixin, TestCase):
    """
    Tests for ``download_child``.
    """

    @async_test
    async def test_not_directory(self) -> None:
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

        dircap = await client.make_directory()
        filecap = await client.upload(get_content)
        await client.link(dircap, "foo", filecap)

        try:
            await download_child(
                outpath,
                client,
                writeable_directory_from_string(dircap).reader,
                ["foo", "somepath"],
            )
        except NotADirectoryError:
            pass
        else:
            self.fail(
                "Expected NotADirectoryError, got return value instead"
            )  # pragma: nocover


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

    def get_client(self) -> ITahoeClient:
        """
        Get the ``ITahoeClient`` provider to test.
        """
        raise NotImplementedError()

    @async_test
    async def test_list_directory(self: TestCase) -> None:
        """
        ``make_directory`` creates a directory the children of which can be listed
        using ``list_directory``.
        """
        tahoe = self.get_client()
        dir_cap = await tahoe.make_directory()
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
                await gatherResults(
                    [Deferred.fromCoroutine(upload(n)) for n in entry_names]
                )
            )
        )
        # Put another directory in it too.
        inner_dir_cap = await tahoe.make_directory()
        await tahoe.link(dir_cap, "directory", inner_dir_cap)

        # Read it back
        children = await tahoe.list_directory(dir_cap)

        self.assertThat(set(children), Equals({"directory"} | set(entry_names)))
        for name in entry_names:
            details = children[name]
            self.assertThat(
                details,
                Equals(
                    FileNode(
                        size=len(file_content(name)),
                        ro_uri=readable_from_string(expected_entry_caps[name]),
                    )
                ),
            )

        details = children["directory"]
        self.assertThat(
            details,
            Equals(
                DirectoryNode(
                    ro_uri=writeable_directory_from_string(inner_dir_cap).reader
                )
            ),
        )

    @async_test
    async def test_list_not_a_directory(self: TestCase) -> None:
        """
        ``list_directory`` returns a coroutine that raises ``ValueError`` when
        called with a capability that is not a directory capability.
        """
        tahoe = self.get_client()

        # Upload not-a-directory
        filecap = await tahoe.upload(lambda: BytesIO(b"hello world"))

        try:
            result = await tahoe.list_directory(filecap)
        except ValueError:
            pass
        else:
            self.fail(f"expected ValueError, got {result!r}")  # pragma: nocover

    @async_test
    async def test_link(self: TestCase) -> None:
        """
        ``link`` adds an entry to a directory.
        """
        tmp = FilePath(self.useFixture(TempDir()).path)
        content = b"some content"
        tahoe = self.get_client()

        dir_cap = await tahoe.make_directory()
        entry_name = "foo"
        entry_cap = await tahoe.upload(lambda: BytesIO(content))
        await tahoe.link(
            dir_cap,
            entry_name,
            entry_cap,
        )

        outpath = tmp.child("destination")
        await download_child(
            outpath,
            tahoe,
            writeable_directory_from_string(dir_cap).reader,
            child_path=[entry_name],
        )

        self.assertThat(
            outpath.getContent(),
            Equals(content),
        )

    @async_test
    async def test_link_readonly(self: TestCase) -> None:
        """
        If ``link`` is passed a read-only directory capability then it returns a
        coroutine that raises ``NotWriteableError``.
        """
        tahoe = self.get_client()
        dir_cap = await tahoe.make_directory()
        ro_dir_cap = attenuate_writecap(dir_cap)

        try:
            result = await tahoe.link(ro_dir_cap, "self", dir_cap)
        except NotWriteableError:
            pass
        else:
            self.fail(
                f"Expected link to fail with NotWriteableError, got {result!r} instead"
            )  # pragma: nocover

    @async_test
    async def test_unlink(self: TestCase) -> None:
        """
        ``unlink`` removes an entry from a directory.
        """
        content = b"some content"
        tahoe = self.get_client()

        # create a directory and put one entry in it
        dir_cap = await tahoe.make_directory()
        entry_name = "foo"
        entry_cap = await tahoe.upload(lambda: BytesIO(content))
        await tahoe.link(
            dir_cap,
            entry_name,
            entry_cap,
        )

        # ensure the file is in the directory
        entries_before = await tahoe.list_directory(dir_cap)
        self.assertThat(list(entries_before.keys()), Equals([entry_name]))

        # unlink the file, leaving the directory empty again
        await tahoe.unlink(dir_cap, entry_name)
        entries_after = await tahoe.list_directory(dir_cap)
        self.assertThat(list(entries_after.keys()), Equals([]))

    @async_test
    async def test_unlink_readonly(self: TestCase) -> None:
        """
        ``unlink`` fails to remove an entry from a read-only directory.
        """
        content = b"some content"
        tahoe = self.get_client()

        # create a directory and put one entry in it
        dir_cap = await tahoe.make_directory()
        entry_name = "foo"
        entry_cap = await tahoe.upload(lambda: BytesIO(content))
        await tahoe.link(
            dir_cap,
            entry_name,
            entry_cap,
        )

        # ensure the file is in the directory
        entries_before = await tahoe.list_directory(dir_cap)
        self.assertThat(list(entries_before.keys()), Equals([entry_name]))

        # try to unlink the file but pass only the read-only cap so we
        # expect failure
        ro_dir_cap = attenuate_writecap(dir_cap)

        try:
            result = await tahoe.unlink(ro_dir_cap, entry_name)
        except NotWriteableError:
            pass
        else:
            self.fail(
                f"Expected link to fail with NotWriteableError, got {result!r} instead"
            )  # pragma: nocover

    @async_test
    async def test_unlink_non_directory(self: TestCase) -> None:
        """
        ``unlink`` fails to remove an entry from "directory capability"
        that isn't actually a directory
        """
        content = b"some content"
        tahoe = self.get_client()

        # create a non-directory
        content = b"some content"
        non_dir_cap = await tahoe.upload(lambda: BytesIO(content))

        # try to unlink some file from the non-directory (expecting
        # failure)
        try:
            result = await tahoe.unlink(non_dir_cap, "foo")
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
            from_awaitable(decorated()),
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
            from_awaitable(decorated()),
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
            from_awaitable(decorated()),
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
        self, needed: int, extra: int, ciphertext_length: int, bytes_per_pass: int
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
