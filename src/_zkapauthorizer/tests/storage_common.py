# Copyright 2019 PrivateStorage.io, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
``allmydata.storage``-related helpers shared across the test suite.
"""

from base64 import b64decode, b64encode
from os import SEEK_CUR
from struct import pack
from typing import Callable, Optional

import attr
from challenge_bypass_ristretto import RandomToken, SigningKey
from twisted.python.filepath import FilePath
from zope.interface import implementer

from ..model import NotEnoughTokens, Pass, UnblindedToken
from ..spending import IPassFactory, PassGroup
from .privacypass import make_passes
from .strategies import bytes_for_share  # Not really a strategy...

# Hard-coded in Tahoe-LAFS
LEASE_INTERVAL = 60 * 60 * 24 * 31


def reset_storage_server(storage_server):
    """
    Restore a storage server to a default state.  This includes
    deleting all of the shares it holds.

    :param allmydata.storage.server.StorageServer storage_server: The storage
        server with some on-disk shares to delete.
    """
    # A storage server is read-write by default.
    storage_server.readonly_storage = False

    starts = [
        FilePath(storage_server.sharedir),
        FilePath(storage_server.corruption_advisory_dir),
    ]
    for start in starts:
        for p in start.walk():
            if p is not start:
                p.remove()


def write_toy_shares(
    storage_server,
    storage_index,
    renew_secret,
    cancel_secret,
    sharenums,
    size,
):
    """
    Write some immutable shares to the given storage server.

    :param allmydata.storage.server.StorageServer storage_server:
    :param bytes storage_index:
    :param bytes renew_secret:
    :param bytes cancel_secret:
    :param set[int] sharenums:
    :param int size:
    """
    _, allocated = storage_server.allocate_buckets(
        storage_index,
        renew_secret,
        cancel_secret,
        sharenums,
        size,
    )
    for (sharenum, writer) in allocated.items():
        writer.write(0, bytes_for_share(sharenum, size))
        writer.close()


def whitebox_write_sparse_share(sharepath, version, size, leases, now):
    """
    Write a zero-filled sparse (if the filesystem supports it) immutable share
    to the given path.

    This assumes knowledge of the Tahoe-LAFS share file format.

    :param FilePath sharepath: The path to which to write the share file.
    :param int version: The share version to write to the file.
    :param int size: The share data size to write.
    :param list leases: Renewal secrets for leases to write to the share file.
    :param float now: The current time as a POSIX timestamp.
    """
    # Maybe-saturated size (what at least one Tahoe-LAFS comment claims is
    # appropriate for large files)
    internal_size = min(size, 2**32 - 1)
    apparent_size = size

    header_format = ">LLL"
    lease_format = ">L32s32sL"
    with sharepath.open("wb") as share:
        share.write(
            pack(
                header_format,
                version,
                internal_size,
                len(leases),
            ),
        )
        # Try to make it sparse by skipping all the data.
        share.seek(apparent_size - 1, SEEK_CUR),
        share.write(b"\0")
        share.write(
            b"".join(
                pack(
                    lease_format,
                    # no owner
                    0,
                    renew,
                    # no cancel secret
                    b"",
                    # expiration timestamp
                    int(now + LEASE_INTERVAL),
                )
                for renew in leases
            ),
        )


def get_passes(message: bytes, count: int, signing_key: SigningKey) -> list[Pass]:
    """
    :param message: Request-binding message for PrivacyPass.

    :param count: The number of passes to get.

    :param signing_key: The key to use to sign the passes.

    :return: ``count`` new random passes signed with the given key
        and bound to the given message.
    """
    assert isinstance(message, bytes)
    return make_passes(
        signing_key,
        message,
        [RandomToken.create() for n in range(count)],
    )


def privacypass_passes(
    signing_key: SigningKey, limit: Optional[int] = None
) -> Callable[[bytes, int], list[Pass]]:
    """
    Get a PrivacyPass issuing function.

    :param signing_key: The key to use to issue passes.

    :param limit: If not None, the maximum number of passes the returned
        function will issue in total.

    :return: Return a function which can be used to get a number of passes.
        The function accepts a request-binding message and a number of passes.
        It returns a list of real pass values signed by the given key.
        Successive calls to the function return unique passes.
    """
    remaining = limit

    def limited_get_passes(message, count):
        nonlocal remaining

        if remaining is not None:
            if count > remaining:
                raise NotEnoughTokens()
            remaining -= count

        return get_passes(message, count, signing_key)

    return limited_get_passes


def pass_factory(get_passes: Callable[[bytes, int], list[Pass]]):
    """
    Get a new factory for passes.

    :param get_passes: A function the factory can use to get new passes.
    """
    return _PassFactory(get_passes=get_passes)


def _pass_to_token(p: Pass) -> UnblindedToken:
    """
    Create an unblinded token from a pass.

    This is not part of the PrivacyPass protocol.  This does not create the
    same unblinded token that was used to create the pass.  This is a
    work-around for the tests wanting to know slightly different things than
    the real implementation, and at slightly different times.  See
    ``_PassFactory``.

    It would probably be an improvement we didn't need this function.
    """
    signature_raw = b64decode(p.signature)
    # expand it to the size required by UnblindedToken
    signature_raw = signature_raw + signature_raw[:32]
    return UnblindedToken(b64encode(signature_raw))


@implementer(IPassFactory)
@attr.s
class _PassFactory(object):
    """
    A stateful pass issuer.

    :ivar _get_passes: A function for getting passes.

    :ivar in_use: All of the unblinded tokens corresponding to passes given
        out which do not have a confirmed terminal state.

    :ivar invalid: All of the unblinded tokens corresponding to passes given
        out and returned using ``IPassGroup.invalid`` mapped to the reason
        given.

    :ivar spent: All of the unblinded tokens corresponding to passes given out
        and returned via ``IPassGroup.mark_spent``.

    :ivar issued: All of the unblinded tokens corresponding to passes ever
        given out.

    :ivar returned: A list of the unblinded tokens corresponding to passes
        which were given out but then returned via ``IPassGroup.reset``.
    """

    _get_passes: Callable[[bytes, int], list[Pass]] = attr.ib()

    returned: list[UnblindedToken] = attr.ib(default=attr.Factory(list), init=False)
    in_use: set[UnblindedToken] = attr.ib(default=attr.Factory(set), init=False)
    invalid: dict[UnblindedToken, str] = attr.ib(default=attr.Factory(dict), init=False)
    spent: set[UnblindedToken] = attr.ib(default=attr.Factory(set), init=False)
    issued: set[UnblindedToken] = attr.ib(default=attr.Factory(set), init=False)

    # Map unblinded tokens to passes so that we can recover passes from
    # returned unblinded tokens so we can give those passes out again.
    token_to_pass: dict[UnblindedToken, Pass] = attr.ib(
        default=attr.Factory(dict), init=False
    )

    @property
    def spent_passes(self) -> set[Pass]:
        return {self.token_to_pass[t] for t in self.spent}

    @property
    def issued_passes(self) -> set[Pass]:
        return {self.token_to_pass[t] for t in self.issued}

    @property
    def returned_passes(self) -> set[Pass]:
        return {self.token_to_pass[t] for t in self.returned}

    @property
    def invalid_passes(self) -> dict[Pass, str]:
        return {self.token_to_pass[t]: reason for t, reason in self.invalid.items()}

    def get(self, message: bytes, num_passes: int) -> PassGroup:
        passes: list[Pass] = []
        if self.returned:
            passes.extend(self.token_to_pass[t] for t in self.returned[:num_passes])
            del self.returned[:num_passes]
            num_passes -= len(passes)
        passes.extend(self._get_passes(message, num_passes))
        tokens = [_pass_to_token(p) for p in passes]

        pass_info = list(zip(tokens, passes))
        self.token_to_pass.update(pass_info)

        self.issued.update(tokens)
        self.in_use.update(tokens)
        return PassGroup(message, self, pass_info)

    def _clear(self):
        """
        Forget about all passes: returned, in use, spent, invalid, issued.
        """
        del self.returned[:]
        self.in_use.clear()
        self.invalid.clear()
        self.spent.clear()
        self.issued.clear()
        self.token_to_pass.clear()

    def mark_spent(self, unblinded_tokens: list[UnblindedToken]) -> None:
        """
        Check the operation for consistency and update internal book-keeping
        related to the given tokens.

        :raise ValueError: If this state transition is illegal for any of the
            given tokens.
        """
        for t in unblinded_tokens:
            if t not in self.in_use:
                raise ValueError(
                    f"Unblinded token {t} cannot be spent, it is not in use."
                )
        self.spent.update(unblinded_tokens)
        self.in_use.difference_update(unblinded_tokens)

    def mark_invalid(self, reason, unblinded_tokens: list[UnblindedToken]) -> None:
        """
        Check the operation for consistency and update internal book-keeping
        related to the given tokens.

        :raise ValueError: If this state transition is illegal for any of the
            given tokens.
        """
        for t in unblinded_tokens:
            if t not in self.in_use:
                raise ValueError(
                    f"Unblinded token {t} cannot be invalid, it is not in use."
                )
        self.invalid.update(dict.fromkeys(unblinded_tokens, reason))
        self.in_use.difference_update(unblinded_tokens)

    def reset(self, unblinded_tokens: list[UnblindedToken]) -> None:
        """
        Check the operation for consistency and update internal book-keeping
        related to the given tokens.

        :raise ValueError: If this state transition is illegal for any of the
            given tokens.
        """
        for t in unblinded_tokens:
            if t not in self.in_use:
                raise ValueError(
                    f"Unblinded token {t} cannot be reset, it is not in use."
                )
        self.returned.extend(unblinded_tokens)
        self.in_use.difference_update(unblinded_tokens)
