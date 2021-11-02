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

from base64 import (
    b64encode,
    urlsafe_b64encode,
)
from datetime import (
    datetime,
)
from urllib import (
    quote,
)

import attr

from zope.interface import (
    implementer,
)

from hypothesis.strategies import (
    one_of,
    sampled_from,
    just,
    none,
    binary,
    characters,
    text,
    integers,
    sets,
    lists,
    tuples,
    dictionaries,
    fixed_dictionaries,
    builds,
    datetimes,
    recursive,
)

from twisted.internet.defer import (
    succeed,
)
from twisted.internet.task import (
    Clock,
)
from twisted.web.test.requesthelper import (
    DummyRequest,
)

from allmydata.interfaces import (
    IFilesystemNode,
    IDirectoryNode,
    HASH_SIZE,
)

from allmydata.client import (
    config_from_string,
)

from ..model import (
    Pass,
    RandomToken,
    UnblindedToken,
    Voucher,
    Pending,
    DoubleSpend,
    Unpaid,
    Error,
    Redeeming,
    Redeemed,
)

from ..configutil import (
    config_string_from_sections,
)

# Sizes informed by
# https://github.com/brave-intl/challenge-bypass-ristretto/blob/2f98b057d7f353c12b2b12d0f5ae9ad115f1d0ba/src/oprf.rs#L18-L33

# The length of a `TokenPreimage`, in bytes.
_TOKEN_PREIMAGE_LENGTH = 64
# The length of a `Token`, in bytes.
_TOKEN_LENGTH = 96
# The length of a `UnblindedToken`, in bytes.
_UNBLINDED_TOKEN_LENGTH = 96
# The length of a `VerificationSignature`, in bytes.
_VERIFICATION_SIGNATURE_LENGTH = 64


def tahoe_config_texts(storage_client_plugins, shares):
    """
    Build the text of complete Tahoe-LAFS configurations for a node.

    :param storage_client_plugins: A dictionary with storage client plugin
        names as keys.

    :param shares: A strategy to build erasure encoding parameters.  These are
        built as a three-tuple giving (needed, total, happy).  Each element
        may be an integer or None to leave it unconfigured (and rely on the
        default).
    """

    def merge_shares(shares, the_rest):
        for (k, v) in zip(("needed", "happy", "total"), shares):
            if v is not None:
                the_rest["shares." + k] = u"{}".format(v)
        return the_rest

    client_section = builds(
        merge_shares,
        shares,
        fixed_dictionaries(
            {
                "storage.plugins": just(
                    u",".join(storage_client_plugins.keys()),
                ),
            },
        ),
    )

    return builds(
        lambda *sections: config_string_from_sections(
            sections,
        ),
        fixed_dictionaries(
            {
                "storageclient.plugins.{}".format(name): configs
                for (name, configs) in storage_client_plugins.items()
            },
        ),
        fixed_dictionaries(
            {
                "node": fixed_dictionaries(
                    {
                        "nickname": node_nicknames(),
                    },
                ),
                "client": client_section,
            },
        ),
    )


def minimal_tahoe_configs(storage_client_plugins=None, shares=just((None, None, None))):
    """
    Build complete Tahoe-LAFS configurations for a node.

    :param shares: See ``tahoe_config_texts``.

    :return SearchStrategy[unicode]: A strategy that builds unicode strings
        which are Tahoe-LAFS configuration file contents.
    """
    if storage_client_plugins is None:
        storage_client_plugins = {}
    return tahoe_config_texts(
        storage_client_plugins,
        shares,
    )


def node_nicknames():
    """
    Builds Tahoe-LAFS node nicknames.
    """
    return text(
        min_size=0,
        max_size=16,
        alphabet=characters(
            blacklist_categories={
                # Surrogates
                u"Cs",
                # Unnamed and control characters
                u"Cc",
            },
        ),
    )


def dummy_ristretto_keys():
    """
    Build string values which one could imagine might be Ristretto-flavored
    PrivacyPass signing or public keys.

    They're not really because they're entirely random rather than points on
    the curve.
    """
    return (
        binary(
            min_size=32,
            max_size=32,
        )
        .map(
            b64encode,
        )
        .map(
            lambda bs: bs.decode("ascii"),
        )
    )


def server_configurations(signing_key_path):
    """
    Build configuration values for the server-side plugin.

    :param unicode signing_key_path: A value to insert for the
        **ristretto-signing-key-path** item.
    """
    return one_of(
        fixed_dictionaries(
            {
                u"pass-value":
                # The configuration is ini so everything is always a byte string!
                integers(min_value=1).map(bytes),
            }
        ),
        just({}),
    ).map(
        lambda config: config.update(
            {
                u"ristretto-issuer-root-url": u"https://issuer.example.invalid/",
                u"ristretto-signing-key-path": signing_key_path.path,
            }
        )
        or config,
    )


def dummy_ristretto_keys_sets():
    """
    Build small sets of "dummy" Ristretto keys.  See ``dummy_ristretto_keys``.
    """
    return sets(dummy_ristretto_keys(), min_size=1, max_size=5)


def zkapauthz_configuration(
    extra_configurations,
    allowed_public_keys=dummy_ristretto_keys_sets(),
):
    """
    Build ZKAPAuthorizer client plugin configuration dictionaries.

    :param extra_configurations: A strategy to build any of the optional /
        alternative sections of the configuration.

    :param allowed_public_keys: A strategy to build sets of allowed public
        keys for the configuration.

    :return: A strategy that builds the basic, required part of the client
        plugin configuration plus an extra values built by
        ``extra_configurations``.
    """

    def merge(extra_configuration, allowed_public_keys):
        config = {
            u"default-token-count": u"32",
            u"allowed-public-keys": u",".join(allowed_public_keys),
        }
        config.update(extra_configuration)
        return config

    return builds(
        merge,
        extra_configurations,
        allowed_public_keys,
    )


def client_ristrettoredeemer_configurations():
    """
    Build Ristretto-using configuration values for the client-side plugin.
    """
    return zkapauthz_configuration(
        just(
            {
                u"ristretto-issuer-root-url": u"https://issuer.example.invalid/",
                u"redeemer": u"ristretto",
            }
        )
    )


def client_dummyredeemer_configurations():
    """
    Build DummyRedeemer-using configuration values for the client-side plugin.
    """

    def share_a_key(allowed_keys):
        return zkapauthz_configuration(
            just(
                {
                    u"redeemer": u"dummy",
                    # Pick out one of the allowed public keys so that the dummy
                    # appears to produce usable tokens.
                    u"issuer-public-key": next(iter(allowed_keys)),
                }
            ),
            allowed_public_keys=just(allowed_keys),
        )

    return dummy_ristretto_keys_sets().flatmap(share_a_key)


def token_counts():
    """
    Build integers that are plausible as a number of tokens to receive in
    exchange for a voucher.
    """
    return integers(min_value=16, max_value=2 ** 16)


def client_doublespendredeemer_configurations(default_token_counts=token_counts()):
    """
    Build DoubleSpendRedeemer-using configuration values for the client-side plugin.
    """
    return zkapauthz_configuration(
        just(
            {
                u"redeemer": u"double-spend",
            }
        )
    )


def client_unpaidredeemer_configurations():
    """
    Build UnpaidRedeemer-using configuration values for the client-side plugin.
    """
    return zkapauthz_configuration(
        just(
            {
                u"redeemer": u"unpaid",
            }
        )
    )


def client_nonredeemer_configurations():
    """
    Build NonRedeemer-using configuration values for the client-side plugin.
    """
    return zkapauthz_configuration(
        just(
            {
                u"redeemer": u"non",
            }
        )
    )


def client_errorredeemer_configurations(details):
    """
    Build ErrorRedeemer-using configuration values for the client-side plugin.
    """
    return zkapauthz_configuration(
        just(
            {
                u"redeemer": u"error",
                u"details": details,
            }
        )
    )


def direct_tahoe_configs(
    zkapauthz_v1_configuration=client_dummyredeemer_configurations(),
    shares=just((None, None, None)),
):
    """
    Build complete Tahoe-LAFS configurations including the zkapauthorizer
    client plugin section.

    :param shares: See ``tahoe_config_texts``.

    :return SearchStrategy[_Config]: A strategy that builds Tahoe config
        objects.
    """
    config_texts = minimal_tahoe_configs(
        {
            u"privatestorageio-zkapauthz-v1": zkapauthz_v1_configuration,
        },
        shares,
    )
    return config_texts.map(
        lambda config_text: config_from_string(
            u"/dev/null/illegal",
            u"",
            config_text.encode("utf-8"),
        ),
    )


def tahoe_configs(
    zkapauthz_v1_configuration=client_dummyredeemer_configurations(),
    shares=just((None, None, None)),
):
    """
    Build complete Tahoe-LAFS configurations including the zkapauthorizer
    client plugin section.

    You probably want ``direct_tahoe_configs``.

    :param shares: See ``tahoe_config_texts``.

    :return SearchStrategy[str -> str -> _Config]: A strategy that builds
        two-argument functions that return a config object.  The two arguments
        are the ``basedir`` and ``portnumfile`` arguments to Tahoe's
        ``config_from_string.``
    """

    def path_setter(config):
        def set_paths(basedir, portnumfile):
            config._basedir = basedir.decode("ascii")
            config.portnum_fname = portnumfile
            return config

        return set_paths

    return direct_tahoe_configs(zkapauthz_v1_configuration, shares,).map(
        path_setter,
    )


def share_parameters():
    """
    Build three-tuples of integers giving usable k, happy, N parameters to
    Tahoe-LAFS' erasure encoding process.
    """
    return lists(integers(min_value=1, max_value=255), min_size=3, max_size=3,).map(
        sorted,
    )


def vouchers():
    """
    Build unicode strings in the format of vouchers.
    """
    return (
        binary(
            min_size=32,
            max_size=32,
        )
        .map(
            urlsafe_b64encode,
        )
        .map(
            lambda voucher: voucher.decode("ascii"),
        )
    )


def redeemed_states():
    """
    Build ``Redeemed`` instances.
    """
    return builds(
        Redeemed,
        finished=datetimes(),
        token_count=one_of(integers(min_value=1)),
    )


def voucher_counters():
    """
    Build integers usable as counters in the voucher redemption process.
    """
    return integers(
        min_value=0,
        # This may or may not be the actual maximum value accepted by a
        # PaymentServer.  If it is not exactly the maximum, it's probably at
        # least in the same ballpark.
        max_value=256,
    )


def voucher_states():
    """
    Build Python objects representing states a Voucher can be in.
    """
    return one_of(
        builds(
            Pending,
            counter=integers(min_value=0),
        ),
        builds(
            Redeeming,
            started=datetimes(),
            counter=voucher_counters(),
        ),
        redeemed_states(),
        builds(
            DoubleSpend,
            finished=datetimes(),
        ),
        builds(
            Unpaid,
            finished=datetimes(),
        ),
        builds(
            Error,
            finished=datetimes(),
            details=text(),
        ),
    )


def voucher_objects(states=voucher_states()):
    """
    Build ``Voucher`` instances.
    """
    return builds(
        Voucher,
        number=vouchers(),
        created=one_of(none(), datetimes()),
        expected_tokens=integers(min_value=1),
        state=states,
    )


def redemption_group_counts():
    """
    Build integers which can represent the number of groups in the redemption
    process.
    """
    return integers(
        min_value=1,
        # Make this similar to the max_value of voucher_counters since those
        # counters count through the groups.
        max_value=256,
    )


def byte_strings(label, length, entropy):
    """
    Build byte strings of the given length with at most the given amount of
    entropy.

    These are cheaper for Hypothesis to construct than byte strings where
    potentially the entire length is random.
    """
    if len(label) + entropy > length:
        raise ValueError(
            "Entropy and label don't fit into {} bytes".format(
                length,
            )
        )
    return binary(min_size=entropy, max_size=entropy,).map(
        lambda bs: label + b"x" * (length - entropy - len(label)) + bs,
    )


def random_tokens():
    """
    Build ``RandomToken`` instances.
    """
    return (
        byte_strings(
            label=b"random-tokens",
            length=_TOKEN_LENGTH,
            entropy=4,
        )
        .map(
            b64encode,
        )
        .map(
            lambda token: RandomToken(token.decode("ascii")),
        )
    )


def token_preimages():
    """
    Build ``unicode`` strings representing base64-encoded token preimages.
    """
    return byte_strings(
        label=b"token-preimage",
        length=_TOKEN_PREIMAGE_LENGTH,
        entropy=4,
    ).map(
        lambda bs: b64encode(bs).decode("ascii"),
    )


def verification_signatures():
    """
    Build ``unicode`` strings representing base64-encoded verification
    signatures.
    """
    return byte_strings(
        label=b"verification-signature",
        length=_VERIFICATION_SIGNATURE_LENGTH,
        entropy=4,
    ).map(
        lambda bs: b64encode(bs).decode("ascii"),
    )


def zkaps():
    """
    Build random ZKAPs as ``Pass`` instances.
    """
    return builds(
        Pass,
        preimage=token_preimages(),
        signature=verification_signatures(),
    )


def unblinded_tokens():
    """
    Builds random ``_zkapauthorizer.model.UnblindedToken`` wrapping invalid
    base64 encode data.  You cannot use these in the PrivacyPass cryptographic
    protocol but you can put them into the database and take them out again.
    """
    return (
        byte_strings(
            label=b"unblinded-tokens",
            length=_UNBLINDED_TOKEN_LENGTH,
            entropy=4,
        )
        .map(
            b64encode,
        )
        .map(
            lambda zkap: UnblindedToken(zkap.decode("ascii")),
        )
    )


def request_paths():
    """
    Build lists of byte strings that represent the path component of an HTTP
    request.

    :see: ``requests``
    """
    return lists(text().map(lambda x: quote(x.encode("utf-8"), safe=b"")))


def requests(paths=request_paths()):
    """
    Build objects providing ``twisted.web.iweb.IRequest``.
    """
    return builds(
        DummyRequest,
        paths,
    )


def storage_indexes():
    """
    Build Tahoe-LAFS storage indexes.
    """
    return binary(
        # It is tempting to use StorageIndex.minLength and
        # StorageIndex.maxLength but these are effectively garbage.  See the
        # implementation of ByteStringConstraint for details.
        min_size=16,
        max_size=16,
    )


def lease_renew_secrets():
    """
    Build Tahoe-LAFS lease renewal secrets.
    """
    return binary(
        min_size=HASH_SIZE,
        max_size=HASH_SIZE,
    )


def lease_cancel_secrets():
    """
    Build Tahoe-LAFS lease cancellation secrets.
    """
    return binary(
        min_size=HASH_SIZE,
        max_size=HASH_SIZE,
    )


def write_enabler_secrets():
    """
    Build Tahoe-LAFS write enabler secrets.
    """
    return binary(
        min_size=HASH_SIZE,
        max_size=HASH_SIZE,
    )


def share_versions():
    """
    Build integers which could be Tahoe-LAFS share file version numbers.
    """
    return integers(min_value=0, max_value=2 ** 32 - 1)


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
        max_size=256,
    )


def sizes(
    # Size 0 data isn't data, it's nothing.
    min_value=1,
    # Let this be larger than a single segment (2 ** 17) in case that matters
    # to Tahoe-LAFS storage at all.  I don't think it does, though.
    max_value=2 ** 18,
):
    """
    Build Tahoe-LAFS share sizes.
    """
    return integers(
        min_value=min_value,
        max_value=max_value,
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
    return tuples(sharenums(), sizes()).map(
        lambda num_and_size: bytes_for_share(*num_and_size),
    )


def slot_data_vectors():
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


def slot_test_vectors():
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


def slot_test_and_write_vectors():
    """
    Build Tahoe-LAFS test and write vectors for a single share.
    """
    return builds(
        TestAndWriteVectors,
        slot_test_vectors(),
        slot_data_vectors(),
        one_of(
            just(None),
            sizes(),
        ),
    )


def slot_test_and_write_vectors_for_shares():
    """
    Build Tahoe-LAFS test and write vectors for a number of shares.
    """
    return dictionaries(
        sharenums(),
        slot_test_and_write_vectors(),
        # An empty dictionary wouldn't make much sense.  And it provokes a
        # NameError from Tahoe, storage/server.py:479, `new_length` referenced
        # before assignment.
        min_size=1,
        # Just for practical purposes...
        max_size=4,
    )


def announcements():
    """
    Build announcements for the ZKAPAuthorizer plugin.
    """
    return just(
        {
            u"ristretto-issuer-root-url": u"https://issuer.example.invalid/",
        }
    )


_POSIX_EPOCH = datetime.utcfromtimestamp(0)


def posix_safe_datetimes():
    """
    Build datetime instances in a range that can be represented as floats
    without losing microsecond precision.
    """
    return datetimes(
        # I don't know that time-based parts of the system break down
        # before the POSIX epoch but I don't know that they work, either.
        # Don't time travel with this code.
        min_value=_POSIX_EPOCH,
        # Once we get far enough into the future we lose the ability to
        # represent a timestamp with microsecond precision in a floating point
        # number, which we do with any POSIX timestamp-like API (eg
        # twisted.internet.task.Clock).  So don't go far enough into the
        # future.  Furthermore, once we don't fit into an unsigned 4 byte
        # integers, we can't round-trip through all the things that expect a
        # time_t.  Stay back from the absolute top to give tests a little
        # space to advance time, too.
        max_value=datetime.utcfromtimestamp(2 ** 31),
    )


def posix_timestamps():
    """
    Build floats in a range that can represent time without losing microsecond
    precision.
    """
    return posix_safe_datetimes().map(
        lambda when: (when - _POSIX_EPOCH).total_seconds(),
    )


def clocks(now=posix_timestamps()):
    """
    Build ``twisted.internet.task.Clock`` instances set to a time built by
    ``now``.

    :param now: A strategy that builds POSIX timestamps (ie, ints or floats in
        the range of time_t).
    """

    def clock_at_time(when):
        c = Clock()
        c.advance(when)
        return c

    return now.map(clock_at_time)


@implementer(IFilesystemNode)
@attr.s(frozen=True)
class _LeafNode(object):
    _storage_index = attr.ib()

    def get_storage_index(self):
        return self._storage_index

    # For testing
    def flatten(self):
        return [self]


def leaf_nodes():
    return storage_indexes().map(_LeafNode)


@implementer(IDirectoryNode)
@attr.s
class _DirectoryNode(object):
    _storage_index = attr.ib()
    _children = attr.ib()

    def list(self):
        return succeed(self._children)

    def get_storage_index(self):
        return self._storage_index

    # For testing
    def flatten(self):
        result = [self]
        for (node, _) in self._children.values():
            result.extend(node.flatten())
        return result


def directory_nodes(child_strategy):
    """
    Build directory nodes with children drawn from the given strategy.
    """
    children = dictionaries(
        text(),
        tuples(
            child_strategy,
            just({}),
        ),
    )
    return builds(
        _DirectoryNode,
        storage_indexes(),
        children,
    )


def node_hierarchies():
    """
    Build hierarchies of ``IDirectoryNode`` and other ``IFilesystemNode``
    (incomplete) providers.
    """

    def storage_indexes_are_distinct(nodes):
        seen = set()
        for n in nodes.flatten():
            si = n.get_storage_index()
            if si in seen:
                return False
            seen.add(si)
        return True

    return recursive(leaf_nodes(), directory_nodes,).filter(
        storage_indexes_are_distinct,
    )


def pass_counts():
    """
    Build integers usable as a number of passes to work on.  There is always
    at least one pass in a group and there are never "too many", whatever that
    means.
    """
    return integers(min_value=1, max_value=2 ** 8)


def api_auth_tokens():
    """
    Build byte strings like those generated by Tahoe-LAFS for use as HTTP API
    authorization tokens.
    """
    return binary(min_size=32, max_size=32).map(b64encode)


def ristretto_signing_keys():
    """
    Build byte strings holding base64-encoded Ristretto signing keys, perhaps
    with leading or trailing whitespace.
    """
    keys = sampled_from(
        [
            # A few legit keys
            b"mkQf85V2vyLQRUYuqRb+Ke6K+M9pOtXm4MslsuCdBgg=",
            b"6f93OIdZHHAmSIaRXDSIU1UcN+sbDAh41TRPb5DhrgI=",
            b"k58h8yPT18epw+EKMJhwHFfoM6r3TIExKm4efQHNBgM=",
            b"rbaAlWZ3NCnl5oZ9meviGfpLbyJpgpuiuFOX0rLnNwQ=",
        ]
    )
    whitespace = sampled_from(
        [
            # maybe no whitespace at all
            b""
            # or maybe some
            b" ",
            b"\t",
            b"\n",
            b"\r\n",
        ]
    )

    return builds(
        lambda leading, key, trailing: leading + key + trailing,
        whitespace,
        keys,
        whitespace,
    )
