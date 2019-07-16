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
Hypothesis strategies for property testing.
"""

import attr

from hypothesis.strategies import (
    one_of,
    just,
    binary,
    integers,
    sets,
    lists,
    tuples,
    dictionaries,
    builds,
)

from allmydata.interfaces import (
    StorageIndex,
    LeaseRenewSecret,
    LeaseCancelSecret,
    WriteEnablerSecret,
)

def configurations():
    """
    Build configuration values for the plugin.
    """
    return just({})


def storage_indexes():
    """
    Build Tahoe-LAFS storage indexes.
    """
    return binary(
        min_size=StorageIndex.minLength,
        max_size=StorageIndex.maxLength,
    )


def lease_renew_secrets():
    """
    Build Tahoe-LAFS lease renewal secrets.
    """
    return binary(
        min_size=LeaseRenewSecret.minLength,
        max_size=LeaseRenewSecret.maxLength,
    )


def lease_cancel_secrets():
    """
    Build Tahoe-LAFS lease cancellation secrets.
    """
    return binary(
        min_size=LeaseCancelSecret.minLength,
        max_size=LeaseCancelSecret.maxLength,
    )


def write_enabler_secrets():
    """
    Build Tahoe-LAFS write enabler secrets.
    """
    return binary(
        min_size=WriteEnablerSecret.minLength,
        max_size=WriteEnablerSecret.maxLength,
    )


def sharenums():
    """
    Build Tahoe-LAFS share numbers.
    """
    return integers(
        min_value=0,
        max_value=255,
    )


def sharenum_sets():
    """
    Build sets of Tahoe-LAFS share numbers.
    """
    return sets(
        sharenums(),
        min_size=1,
        max_size=255,
    )


def sizes():
    """
    Build Tahoe-LAFS share sizes.
    """
    return integers(
        # Size 0 data isn't data, it's nothing.
        min_value=1,
        # Just for practical purposes...
        max_value=2 ** 16,
    )


def offsets():
    """
    Build Tahoe-LAFS share offsets.
    """
    return integers(
        min_value=0,
        # Just for practical purposes...
        max_value=2 ** 16,
    )


def bytes_for_share(sharenum, size):
    """
    :return bytes: marginally distinctive bytes of a certain length for the
        given share number
    """
    if 0 <= sharenum <= 255:
        return (unichr(sharenum) * size).encode("latin-1")
    raise ValueError("Sharenum must be between 0 and 255 inclusive.")


def shares():
    """
    Build Tahoe-LAFS share data.
    """
    return tuples(
        sharenums(),
        sizes()
    ).map(
        lambda num_and_size: bytes_for_share(*num_and_size),
    )


def data_vectors():
    """
    Build Tahoe-LAFS data vectors.
    """
    return lists(
        tuples(
            offsets(),
            shares(),
        ),
        # An empty data vector doesn't make much sense.  If you have no data
        # to write, you should probably use slot_readv instead.  Also,
        # Tahoe-LAFS explodes if you pass an empty data vector -
        # storage/server.py, OSError(ENOENT) from `os.listdir(bucketdir)`.
        min_size=1,
        # Just for practical purposes...
        max_size=8,
    )


def test_vectors():
    """
    Build Tahoe-LAFS test vectors.
    """
    return lists(
        # XXX TODO
        just(None),
        min_size=0,
        max_size=0,
    )


@attr.s(frozen=True)
class TestAndWriteVectors(object):
    """
    Provide an alternate structure for the values required by the
    ``tw_vectors`` parameter accepted by
    ``RIStorageServer.slot_testv_and_readv_and_writev``.
    """
    test_vector = attr.ib()
    write_vector = attr.ib()
    new_length = attr.ib()

    def for_call(self):
        """
        Construct a value suitable to be passed as ``tw_vectors`` to
        ``slot_testv_and_readv_and_writev``.
        """
        return (self.test_vector, self.write_vector, self.new_length)


def test_and_write_vectors():
    """
    Build Tahoe-LAFS test and write vectors for a single share.
    """
    return builds(
        TestAndWriteVectors,
        test_vectors(),
        data_vectors(),
        one_of(
            just(None),
            sizes(),
        ),
    )


def test_and_write_vectors_for_shares():
    """
    Build Tahoe-LAFS test and write vectors for a number of shares.
    """
    return dictionaries(
        sharenums(),
        test_and_write_vectors(),
        # An empty dictionary wouldn't make much sense.  And it provokes a
        # NameError from Tahoe, storage/server.py:479, `new_length` referenced
        # before assignment.
        min_size=1,
        # Just for practical purposes...
        max_size=8,
    )


def announcements():
    """
    Build announcements for the SecureAccessTokenAuthorizer plugin.
    """
    return just({})
