"""
Tests for ``_zkapauthorizer.tahoe``.
"""

from asyncio import run

from allmydata.test.strategies import write_capabilities
from fixtures import TempDir
from hyperlink import DecodedURL
from hypothesis import given
from hypothesis.strategies import integers, lists, sampled_from, text, tuples
from testresources import setUpResources, tearDownResources
from testtools import TestCase
from testtools.matchers import Equals, Is, Not, raises
from testtools.twistedsupport import AsynchronousDeferredRunTest
from twisted.internet.defer import Deferred, ensureDeferred, inlineCallbacks
from twisted.python.filepath import FilePath

from ..tahoe import (
    TahoeAPIError,
    _scrub_cap,
    async_retry,
    download,
    link,
    make_directory,
    upload,
)
from .fixtures import Treq
from .resources import client_manager


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


class UploadDownloadTestCase(TestCase):
    """
    Tests for ``upload`` and ``download``.
    """

    # Support test methods that return a Deferred.
    run_tests_with = AsynchronousDeferredRunTest.make_factory(timeout=60.0)

    # Get a Tahoe-LAFS client node connected to a storage node.
    resources = [("client", client_manager)]

    def setUp(self):
        super().setUp()
        setUpResources(self, self.resources, None)
        self.addCleanup(lambda: tearDownResources(self, self.resources, None))

    @inlineCallbacks
    def test_found(self):
        """
        If the identified object can be downloaded then it is written to the given
        path.
        """
        # AsynchronousDeferredRunTest sets reactor on us.
        client = self.useFixture(Treq(self.reactor, case=self)).client()

        workdir = FilePath(self.useFixture(TempDir()).join("test_found"))
        workdir.makedirs()
        inpath = workdir.child("uploaded")
        inpath.setContent(b"abc" * 1024)
        outpath = workdir.child("downloaded")

        cap = yield ensureDeferred(upload(client, inpath, self.client.node_url))
        yield ensureDeferred(download(client, outpath, self.client.node_url, cap))

        self.assertThat(
            inpath.getContent(),
            Equals(outpath.getContent()),
        )


class DirectoryTests(TestCase):
    """
    Tests for directory-related functionality.
    """

    # Support test methods that return a Deferred.
    run_tests_with = AsynchronousDeferredRunTest.make_factory(timeout=60.0)

    # Get a Tahoe-LAFS client node connected to a storage node.
    resources = [("client", client_manager)]

    def setUp(self):
        super().setUp()
        setUpResources(self, self.resources, None)
        self.addCleanup(lambda: tearDownResources(self, self.resources, None))
        # AsynchronousDeferredRunTest sets reactor on us.
        self.httpclient = self.useFixture(Treq(self.reactor, case=self)).client()

    @inlineCallbacks
    def test_make_directory(self):
        """
        ``make_directory`` returns a coroutine that completes with the capability
        of a new, empty directory.
        """
        dir_cap = yield Deferred.fromCoroutine(
            make_directory(self.httpclient, self.client.node_url)
        )

        # If we can download it, consider that success.
        outpath = FilePath(self.useFixture(TempDir()).join("dir_contents"))
        yield Deferred.fromCoroutine(
            download(self.httpclient, outpath, self.client.node_url, dir_cap)
        )
        self.assertThat(outpath.getContent(), Not(Equals(b"")))

    @inlineCallbacks
    def test_link(self):
        """
        ``link`` adds an entry to a directory.
        """
        tmp = FilePath(self.useFixture(TempDir()).path)
        inpath = tmp.child("source")
        inpath.setContent(b"some content")

        dir_cap = yield Deferred.fromCoroutine(
            make_directory(self.httpclient, self.client.node_url)
        )
        entry_name = "foo"
        entry_cap = yield Deferred.fromCoroutine(
            upload(self.httpclient, inpath, self.client.node_url),
        )
        yield Deferred.fromCoroutine(
            link(
                self.httpclient,
                self.client.node_url,
                dir_cap,
                entry_name,
                entry_cap,
            ),
        )

        outpath = tmp.child("destination")
        yield Deferred.fromCoroutine(
            download(
                self.httpclient,
                outpath,
                self.client.node_url,
                dir_cap,
                child_path=[entry_name],
            ),
        )

        self.assertThat(
            outpath.getContent(),
            Equals(inpath.getContent()),
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

        coro = decorated()
        self.assertThat(
            run(coro),
            Is(result),
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

        coro = decorated()
        self.assertThat(
            lambda: run(coro),
            raises(Exc),
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

        coro = decorated()
        self.assertThat(
            run(coro),
            Is(result),
        )
