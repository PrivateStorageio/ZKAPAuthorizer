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

from base64 import b64encode, urlsafe_b64encode
from datetime import datetime, timedelta, timezone
from functools import partial
from typing import Any, Callable, Optional, TypeVar, cast
from urllib.parse import quote

import attr
from allmydata.client import config_from_string
from allmydata.interfaces import HASH_SIZE, IDirectoryNode, IFilesystemNode
from attrs import frozen
from hypothesis.strategies import SearchStrategy, binary, builds, characters
from hypothesis.strategies import datetimes as naive_datetimes
from hypothesis.strategies import (
    dictionaries,
    fixed_dictionaries,
    floats,
    integers,
    just,
    lists,
    none,
    one_of,
    recursive,
    sampled_from,
    sets,
    text,
    tuples,
)
from twisted.internet.defer import Deferred, succeed
from twisted.internet.task import Clock
from twisted.python.filepath import FilePath
from twisted.web.test.requesthelper import DummyRequest
from zope.interface import implementer

from .. import NAME
from .._types import (
    ClientConfig,
    DoubleSpendRedeemerConfig,
    DummyRedeemerConfig,
    ErrorRedeemerConfig,
    NonRedeemerConfig,
    ServerConfig,
    UnpaidRedeemerConfig,
)
from ..config import Config
from ..configutil import config_string_from_sections
from ..lease_maintenance import LeaseMaintenanceConfig, lease_maintenance_config_to_dict
from ..model import (
    DoubleSpend,
    Error,
    Pass,
    Pending,
    RandomToken,
    Redeemed,
    Redeeming,
    UnblindedToken,
    Unpaid,
    Voucher,
    VoucherState,
)
from ..sql import (
    Column,
    Delete,
    Insert,
    Select,
    SQLType,
    Statement,
    StorageAffinity,
    Table,
    Update,
)
from ..storage_common import (
    ClientTestVector,
    ClientTestWriteVector,
    DataVector,
    ServerTestVector,
    ServerTestWriteVector,
)
from ..validators import non_negative_integer, positive_integer
from .common import GetConfig

_POSIX_EPOCH = datetime.utcfromtimestamp(0).replace(tzinfo=timezone.utc)


def aware_datetimes(
    allow_imaginary: bool = True, **kwargs: datetime
) -> SearchStrategy[datetime]:
    """
    Build timezone-aware (UTC) datetime instances.
    """
    return naive_datetimes(
        timezones=just(timezone.utc), allow_imaginary=allow_imaginary, **kwargs
    )


def posix_safe_datetimes() -> SearchStrategy[datetime]:
    """
    Build datetime instances in a range that can be represented as floats
    without losing microsecond precision.
    """
    return aware_datetimes(
        # I don't know that time-based parts of the system break down
        # before the POSIX epoch but I don't know that they work, either.
        # Don't time travel with this code.
        min_value=datetime.utcfromtimestamp(0),
        # Once we get far enough into the future we lose the ability to
        # represent a timestamp with microsecond precision in a floating point
        # number, which we do with any POSIX timestamp-like API (eg
        # twisted.internet.task.Clock).  So don't go far enough into the
        # future.  Furthermore, once we don't fit into an unsigned 4 byte
        # integers, we can't round-trip through all the things that expect a
        # time_t.  Stay back from the absolute top to give tests a little
        # space to advance time, too.
        max_value=datetime.utcfromtimestamp(2**31),
    )


def posix_timestamps() -> SearchStrategy[float]:
    """
    Build floats in a range that can represent time without losing microsecond
    precision.
    """
    return posix_safe_datetimes().map(
        lambda when: (when - _POSIX_EPOCH).total_seconds(),
    )


def clocks(now: SearchStrategy[float] = posix_timestamps()) -> SearchStrategy[Clock]:
    """
    Build ``twisted.internet.task.Clock`` instances set to a time built by
    ``now``.

    :param now: A strategy that builds POSIX timestamps (ie, ints or floats in
        the range of time_t).
    """

    def clock_at_time(when: float) -> Clock:
        c = Clock()
        c.advance(when)
        return c

    return now.map(clock_at_time)


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


def encoding_parameters() -> SearchStrategy[tuple[int, int, int]]:
    """
    Build three-tuples of integers that can be used as needed, happy, total
    encoding/share placement parameters for a Tahoe-LAFS client node.

    :return: (n, h, k) such that 1 <= n <= h <= k <= 255
    """

    def order(xs: list[int]) -> tuple[int, int, int]:
        xs.sort()
        return (xs[0], xs[1], xs[2])

    return lists(
        integers(min_value=1, max_value=255),
        min_size=3,
        max_size=3,
    ).map(order)


EncodingParameters = tuple[Optional[int], Optional[int], Optional[int]]


def tahoe_config_texts(
    storage_client_plugins: dict[str, SearchStrategy[object]],
    shares: SearchStrategy[EncodingParameters],
) -> SearchStrategy[str]:
    """
    Build the text of complete Tahoe-LAFS configurations for a node.

    :param storage_client_plugins: A dictionary with storage client plugin
        names as keys.

    :param shares: A strategy to build erasure encoding parameters.  These are
        built as a three-tuple giving (needed, total, happy).  Each element
        may be an integer or None to leave it unconfigured (and rely on the
        default).
    """

    def merge_shares(
        shares: tuple[int, int, int], the_rest: dict[str, object]
    ) -> dict[str, object]:
        for k, v in zip(("needed", "happy", "total"), shares):
            if v is not None:
                the_rest["shares." + k] = f"{v}"
        return the_rest

    client_section = builds(
        merge_shares,
        shares,
        fixed_dictionaries(
            {
                "storage.plugins": just(
                    ",".join(storage_client_plugins.keys()),
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


def minimal_tahoe_configs(
    storage_client_plugins: Optional[dict[str, SearchStrategy[object]]] = None,
    shares: SearchStrategy[EncodingParameters] = just((None, None, None)),
) -> SearchStrategy[str]:
    """
    Build complete Tahoe-LAFS configurations for a node.

    :param shares: See ``tahoe_config_texts``.

    :return SearchStrategy[str]: A strategy that builds text strings which are
        Tahoe-LAFS configuration file contents.
    """
    if storage_client_plugins is None:
        storage_client_plugins = {}
    return tahoe_config_texts(
        storage_client_plugins,
        shares,
    )


def node_nicknames() -> SearchStrategy[str]:
    """
    Builds Tahoe-LAFS node nicknames.
    """
    return text(
        min_size=0,
        max_size=16,
        alphabet=characters(
            blacklist_categories=(
                # Surrogates
                "Cs",
                # Unnamed and control characters
                "Cc",
            ),
        ),
    )


def dummy_ristretto_keys() -> SearchStrategy[str]:
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


def server_configurations(signing_key_path: FilePath) -> SearchStrategy[ServerConfig]:
    """
    Build configuration values for the server-side plugin.

    :param signing_key_path: A value to insert for the
        **ristretto-signing-key-path** item.
    """

    def add_more(config: dict[Any, Any]) -> ServerConfig:
        config.update(
            {
                "ristretto-issuer-root-url": "https://issuer.example.invalid/",
                "ristretto-signing-key-path": signing_key_path.asTextMode().path,
            }
        )
        return cast(ServerConfig, config)

    return one_of(
        fixed_dictionaries(
            {
                "pass-value":
                # The configuration is ini so everything is always a byte string!
                integers(min_value=1).map(lambda v: f"{v}".encode("ascii")),
            }
        ),
        just({}),
    ).map(add_more)


def dummy_ristretto_keys_sets() -> SearchStrategy[set[str]]:
    """
    Build small sets of "dummy" Ristretto keys.  See ``dummy_ristretto_keys``.
    """
    return sets(dummy_ristretto_keys(), min_size=1, max_size=5)


def zkapauthz_configuration(
    extra_configurations: SearchStrategy[ClientConfig],
    allowed_public_keys: SearchStrategy[set[str]] = dummy_ristretto_keys_sets(),
) -> SearchStrategy[Config]:
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

    def merge(
        extra_configuration: ClientConfig,
        allowed_public_keys: set[str],
    ) -> ClientConfig:
        config = extra_configuration.copy()
        if config["redeemer"] == "ristretto":
            if "default-token-count" not in config:
                config["default-token-count"] = "32"
        if "allowed-public-keys" not in config:
            config["allowed-public-keys"] = ",".join(allowed_public_keys)  # type: ignore[typeddict-item]
        return config

    return builds(
        merge,
        extra_configurations,
        allowed_public_keys,
    )


def client_ristrettoredeemer_configurations() -> SearchStrategy[ClientConfig]:
    """
    Build Ristretto-using configuration values for the client-side plugin.
    """
    return zkapauthz_configuration(
        just(
            {
                "ristretto-issuer-root-url": "https://issuer.example.invalid/",
                "redeemer": "ristretto",
            }
        )
    )


def client_dummyredeemer_configurations(
    crawl_means: SearchStrategy[Optional[float]] = one_of(none(), posix_timestamps()),
    crawl_ranges: SearchStrategy[Optional[float]] = one_of(none(), posix_timestamps()),
    min_times_remaining: SearchStrategy[Optional[float]] = one_of(
        none(), posix_timestamps()
    ),
) -> SearchStrategy[ClientConfig]:
    """
    Build DummyRedeemer-using configuration values for the client-side plugin.
    """

    def make_lease_config(
        crawl_mean: Optional[float],
        crawl_range: Optional[float],
        min_time_remaining: Optional[float],
    ) -> dict[str, str]:
        config = {}
        if crawl_mean is not None:
            # Don't allow the mean to be 0
            config["lease.crawl-interval.mean"] = str(int(crawl_mean) + 1)
        if crawl_range is not None:
            config["lease.crawl-interval.range"] = str(int(crawl_range))
        if min_time_remaining is not None:
            config["lease.min-time-remaining"] = str(int(min_time_remaining))
        return config

    def share_a_key(allowed_keys: set[str]) -> SearchStrategy[Config]:
        def add_redeemer(lease_config: dict[str, str]) -> DummyRedeemerConfig:
            config: DummyRedeemerConfig = {  # type: ignore[typeddict-item]
                "redeemer": "dummy",
                # Pick out one of the allowed public keys so that the dummy
                # appears to produce usable tokens.
                "issuer-public-key": next(iter(allowed_keys)),
            }
            config.update(lease_config)  # type: ignore[typeddict-item]
            return config

        lease_configs: SearchStrategy[dict[str, str]] = builds(
            make_lease_config,
            crawl_means,
            crawl_ranges,
            min_times_remaining,
        )
        extra_config: SearchStrategy[ClientConfig] = lease_configs.map(add_redeemer)
        return zkapauthz_configuration(
            extra_config,
            allowed_public_keys=just(allowed_keys),
        )

    return dummy_ristretto_keys_sets().flatmap(share_a_key)


def token_counts() -> SearchStrategy[int]:
    """
    Build integers that are plausible as a number of tokens to receive in
    exchange for a voucher.
    """
    return integers(min_value=16, max_value=2**16)


def client_doublespendredeemer_configurations() -> SearchStrategy[ClientConfig]:
    """
    Build DoubleSpendRedeemer-using configuration values for the client-side plugin.
    """
    double_spend: DoubleSpendRedeemerConfig = {"redeemer": "double-spend"}
    return zkapauthz_configuration(just(double_spend))


def client_unpaidredeemer_configurations() -> SearchStrategy[ClientConfig]:
    """
    Build UnpaidRedeemer-using configuration values for the client-side plugin.
    """
    unpaid: UnpaidRedeemerConfig = {"redeemer": "unpaid"}
    return zkapauthz_configuration(just(unpaid))


def client_nonredeemer_configurations() -> SearchStrategy[ClientConfig]:
    """
    Build NonRedeemer-using configuration values for the client-side plugin.
    """
    non: NonRedeemerConfig = {"redeemer": "non"}
    return zkapauthz_configuration(just(non))


def client_errorredeemer_configurations(details: str) -> SearchStrategy[ClientConfig]:
    """
    Build ErrorRedeemer-using configuration values for the client-side plugin.
    """
    error: ErrorRedeemerConfig = {"redeemer": "error", "details": details}
    return zkapauthz_configuration(just(error))


def integer_seconds_timedeltas(
    # Our intervals mostly want to be non-negative.
    min_value: int = 0,
    # We can't make this value too large or it isn't convertable to a
    # timedelta.  Also, even values as large as this one are of
    # questionable value for the durations we measure.
    max_value: int = 60 * 60 * 24 * 365,
) -> SearchStrategy[timedelta]:
    """
    Build ``timedelta`` instances without a fractional seconds part.
    """
    return integers(
        min_value=min_value,
        max_value=max_value,
    ).map(lambda n: timedelta(seconds=n))


def interval_means() -> SearchStrategy[timedelta]:
    """
    Build timedeltas representing the mean time between lease maintenance
    runs.
    """
    return integer_seconds_timedeltas()


def lease_maintenance_configurations() -> SearchStrategy[LeaseMaintenanceConfig]:
    """
    Build LeaseMaintenanceConfig instances.
    """
    return builds(
        LeaseMaintenanceConfig,
        interval_means(),
        integer_seconds_timedeltas(),
        integer_seconds_timedeltas(),
    )


def client_lease_maintenance_configurations(
    maint_configs: Optional[SearchStrategy[LeaseMaintenanceConfig]] = None,
) -> SearchStrategy[ClientConfig]:
    """
    Build dictionaries representing the lease maintenance options that go into
    the ZKAPAuthorizer client plugin section.
    """
    if maint_configs is None:
        maint_configs = lease_maintenance_configurations()
    return maint_configs.map(
        lambda lease_maint_config: cast(
            ClientConfig, lease_maintenance_config_to_dict(lease_maint_config)
        ),
    )


def direct_tahoe_configs(
    zkapauthz_v2_configuration: SearchStrategy[
        ClientConfig
    ] = client_dummyredeemer_configurations(),
    shares: SearchStrategy[tuple[Optional[int], Optional[int], Optional[int]]] = just(
        (None, None, None)
    ),
) -> SearchStrategy[Config]:
    """
    Build complete Tahoe-LAFS configurations including the zkapauthorizer
    client plugin section.

    :param shares: See ``tahoe_config_texts``.

    :return: A strategy that builds Tahoe config objects.
    """
    config_texts = minimal_tahoe_configs(
        {
            NAME: zkapauthz_v2_configuration,
        },
        shares,
    )
    return config_texts.map(
        lambda config_text: config_from_string(
            "/dev/null/illegal",
            "",
            config_text.encode("utf-8"),
        ),
    )


def tahoe_configs(
    zkapauthz_v2_configuration: SearchStrategy[
        ClientConfig
    ] = client_dummyredeemer_configurations(),
    shares: SearchStrategy[tuple[Optional[int], Optional[int], Optional[int]]] = just(
        (None, None, None)
    ),
) -> SearchStrategy[GetConfig]:
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

    def path_setter(config: Config) -> Callable[[str, str], Config]:
        def set_paths(basedir: str, portnumfile: str) -> Config:
            config._basedir = basedir
            config.portnum_fname = portnumfile
            return config

        return set_paths

    return direct_tahoe_configs(
        zkapauthz_v2_configuration,
        shares,
    ).map(
        path_setter,
    )


def vouchers() -> SearchStrategy[bytes]:
    """
    Build byte strings in the format of vouchers.
    """
    return binary(
        min_size=32,
        max_size=32,
    ).map(
        urlsafe_b64encode,
    )


def redeemed_states() -> SearchStrategy[Redeemed]:
    """
    Build ``Redeemed`` instances.
    """
    return builds(
        Redeemed,
        finished=aware_datetimes(),
        token_count=one_of(integers(min_value=1)),
    )


def voucher_counters() -> SearchStrategy[int]:
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


def voucher_states() -> SearchStrategy[VoucherState]:
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
            started=aware_datetimes(),
            counter=voucher_counters(),
        ),
        redeemed_states(),
        builds(
            DoubleSpend,
            finished=aware_datetimes(),
        ),
        builds(
            Unpaid,
            finished=aware_datetimes(),
        ),
        builds(
            Error,
            finished=aware_datetimes(),
            details=text(),
        ),
    )


def voucher_objects(
    states: SearchStrategy[VoucherState] = voucher_states(),
) -> SearchStrategy[Voucher]:
    """
    Build ``Voucher`` instances.
    """
    return builds(
        Voucher,
        number=vouchers(),
        created=one_of(none(), aware_datetimes()),
        expected_tokens=integers(min_value=1),
        state=states,
    )


def redemption_group_counts() -> SearchStrategy[int]:
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


def byte_strings(label: bytes, length: int, entropy: int) -> SearchStrategy[bytes]:
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
    return binary(
        min_size=entropy,
        max_size=entropy,
    ).map(
        lambda bs: label + b"x" * (length - entropy - len(label)) + bs,
    )


def random_tokens() -> SearchStrategy[RandomToken]:
    """
    Build ``RandomToken`` instances.
    """
    return (
        byte_strings(
            label=b"random-tokens",
            length=_TOKEN_LENGTH,
            entropy=4,
        )
        .map(b64encode)
        .map(RandomToken)
    )


def token_preimages() -> SearchStrategy[bytes]:
    """
    Build ``bytes`` strings representing base64-encoded token preimages.
    """
    return byte_strings(
        label=b"token-preimage",
        length=_TOKEN_PREIMAGE_LENGTH,
        entropy=4,
    ).map(b64encode)


def verification_signatures() -> SearchStrategy[bytes]:
    """
    Build ``bytes`` strings representing base64-encoded verification
    signatures.
    """
    return byte_strings(
        label=b"verification-signature",
        length=_VERIFICATION_SIGNATURE_LENGTH,
        entropy=4,
    ).map(b64encode)


def zkaps() -> SearchStrategy[Pass]:
    """
    Build random ZKAPs as ``Pass`` instances.
    """
    return builds(
        Pass,
        preimage=token_preimages(),
        signature=verification_signatures(),
    )


def unblinded_tokens() -> SearchStrategy[UnblindedToken]:
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
        .map(b64encode)
        .map(UnblindedToken)
    )


def request_paths() -> SearchStrategy[list[bytes]]:
    """
    Build lists of byte strings that represent the path component of an HTTP
    request.

    :see: ``requests``
    """

    def quote_segment(seg: str) -> bytes:
        return quote(seg, safe="").encode("utf-8")

    return lists(text().map(quote_segment))


def requests(
    paths: SearchStrategy[list[bytes]] = request_paths(),
) -> SearchStrategy[DummyRequest]:
    """
    Build objects providing ``twisted.web.iweb.IRequest``.
    """
    return builds(
        DummyRequest,
        paths,
    )


def storage_indexes() -> SearchStrategy[bytes]:
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


def lease_renew_secrets() -> SearchStrategy[bytes]:
    """
    Build Tahoe-LAFS lease renewal secrets.
    """
    return binary(
        min_size=HASH_SIZE,
        max_size=HASH_SIZE,
    )


def lease_cancel_secrets() -> SearchStrategy[bytes]:
    """
    Build Tahoe-LAFS lease cancellation secrets.
    """
    return binary(
        min_size=HASH_SIZE,
        max_size=HASH_SIZE,
    )


def write_enabler_secrets() -> SearchStrategy[bytes]:
    """
    Build Tahoe-LAFS write enabler secrets.
    """
    return binary(
        min_size=HASH_SIZE,
        max_size=HASH_SIZE,
    )


def share_versions() -> SearchStrategy[int]:
    """
    Build integers which could be Tahoe-LAFS share file version numbers.
    """
    return integers(min_value=0, max_value=2**32 - 1)


def sharenums() -> SearchStrategy[int]:
    """
    Build Tahoe-LAFS share numbers.
    """
    return integers(
        min_value=0,
        max_value=255,
    )


def sharenum_sets() -> SearchStrategy[set[int]]:
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
    min_value: int = 1,
    # Let this be larger than a single segment (2 ** 17) in case that matters
    # to Tahoe-LAFS storage at all.  I don't think it does, though.
    max_value: int = 2**18,
) -> SearchStrategy[int]:
    """
    Build Tahoe-LAFS share sizes.
    """
    return integers(
        min_value=min_value,
        max_value=max_value,
    )


def offsets() -> SearchStrategy[int]:
    """
    Build Tahoe-LAFS share offsets.
    """
    return integers(
        min_value=0,
        # Just for practical purposes...
        max_value=2**16,
    )


def bytes_for_share(sharenum: int, size: int) -> bytes:
    """
    :return: marginally distinctive bytes of a certain length for the given
        share number
    """
    if 0 <= sharenum <= 255:
        return (chr(sharenum) * size).encode("latin-1")
    raise ValueError("Sharenum must be between 0 and 255 inclusive.")


def shares() -> SearchStrategy[bytes]:
    """
    Build Tahoe-LAFS share data.
    """
    return builds(
        bytes_for_share,
        sharenum=sharenums(),
        size=sizes(),
    )


def slot_data_vectors() -> SearchStrategy[list[tuple[int, bytes]]]:
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


def slot_test_vectors() -> SearchStrategy[list[Optional[object]]]:
    """
    Build Tahoe-LAFS test vectors.
    """
    return lists(
        # XXX TODO
        just(None),
        min_size=0,
        max_size=0,
    )


def to_server_test_vector(v: ClientTestVector) -> ServerTestVector:
    return [(x[0], x[1], b"eq", x[2]) for x in v]


@frozen
class TestAndWriteVectors:
    """
    Provide an alternate structure for the values required by the
    ``tw_vectors`` parameter accepted by
    ``RIStorageServer.slot_testv_and_readv_and_writev``.
    """

    test_vector: ClientTestVector
    write_vector: DataVector
    new_length: Optional[int]

    def for_server(self) -> ServerTestWriteVector:
        """
        Construct a value suitable to be passed as ``tw_vectors`` to the
        server ``slot_testv_and_readv_and_writev``.
        """
        return (
            to_server_test_vector(self.test_vector),
            self.write_vector,
            self.new_length,
        )

    def for_client(
        self,
    ) -> ClientTestWriteVector:
        """
        Construct a value suitable to be passed as ``tw_vectors`` to the
        client ``slot_testv_and_readv_and_writev``.
        """
        return (self.test_vector, self.write_vector, self.new_length)


def slot_test_and_write_vectors() -> SearchStrategy[TestAndWriteVectors]:
    """
    Build Tahoe-LAFS test and write vectors for a single share.
    """
    return builds(
        TestAndWriteVectors,
        slot_test_vectors(),
        slot_data_vectors(),
        # The underlying Tahoe-LAFS storage protocol allows None or an integer
        # here (new_length) to set the size of the mutable container.  The
        # real Tahoe-LAFS storage client never uses this feature and always
        # passes None.  There are undesirable interactions between non-None
        # values for new_length and our spending protocol.  Therefore, we
        # disable non-None values.  So don't generate any here.
        just(None),
    )


def slot_test_and_write_vectors_for_shares() -> (
    SearchStrategy[dict[int, TestAndWriteVectors]]
):
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


def announcements() -> SearchStrategy[dict[str, str]]:
    """
    Build announcements for the ZKAPAuthorizer plugin.
    """
    return just(
        {
            "ristretto-issuer-root-url": "https://issuer.example.invalid/",
        }
    )


@implementer(IFilesystemNode)
@frozen
class _LeafNode(object):
    _storage_index: bytes

    def get_storage_index(self) -> bytes:
        return self._storage_index

    # For testing
    def flatten(self) -> list[IFilesystemNode]:
        return [self]


def leaf_nodes() -> SearchStrategy[_LeafNode]:
    return storage_indexes().map(_LeafNode)


@implementer(IDirectoryNode)
@frozen
class _DirectoryNode(object):
    _storage_index: bytes
    _children: dict[str, IFilesystemNode]

    def get_storage_index(self) -> bytes:
        return self._storage_index

    # For testing
    def flatten(self) -> list[IFilesystemNode]:
        result = [self]
        for node, _ in self._children.values():
            result.extend(node.flatten())
        return result

    def list(self) -> Deferred[dict[str, IFilesystemNode]]:  # noqa: F811
        return succeed(self._children)


def directory_nodes(
    child_strategy: SearchStrategy[IFilesystemNode],
) -> SearchStrategy[_DirectoryNode]:
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


def node_hierarchies() -> SearchStrategy[IFilesystemNode]:
    """
    Build hierarchies of ``IDirectoryNode`` and other ``IFilesystemNode``
    (incomplete) providers.
    """

    def storage_indexes_are_distinct(nodes: IFilesystemNode) -> bool:
        seen = set()
        for n in nodes.flatten():
            si = n.get_storage_index()
            if si in seen:
                return False
            seen.add(si)
        return True

    return recursive(
        leaf_nodes(),
        directory_nodes,
    ).filter(
        storage_indexes_are_distinct,
    )


def pass_counts() -> SearchStrategy[int]:
    """
    Build integers usable as a number of passes to work on.  There is always
    at least one pass in a group and there are never "too many", whatever that
    means.
    """
    return integers(min_value=1, max_value=2**8)


def api_auth_tokens() -> SearchStrategy[bytes]:
    """
    Build byte strings like those generated by Tahoe-LAFS for use as HTTP API
    authorization tokens.
    """
    return binary(min_size=32, max_size=32).map(b64encode)


def ristretto_signing_keys() -> SearchStrategy[bytes]:
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

    def concat(leading: bytes, key: bytes, trailing: bytes) -> bytes:
        return leading + key + trailing

    return builds(
        concat,
        whitespace,
        keys,
        whitespace,
    )


@attr.s(frozen=True)
class _VoucherInsert(object):
    """
    Represent the insertion of a single voucher.
    """

    voucher: bytes = attr.ib()
    expected_tokens: int = attr.ib(validator=positive_integer)
    counter: int = attr.ib(validator=non_negative_integer)
    tokens: list[RandomToken] = attr.ib()


@attr.s(frozen=True)
class ExistingState(object):
    """
    Represent some state which could already exist in a ``VoucherStore``.
    """

    vouchers: list[_VoucherInsert] = attr.ib()


def existing_states(
    min_vouchers: int = 0, max_vouchers: int = 4
) -> SearchStrategy[ExistingState]:
    """
    Build possible existing states of a ``VoucherStore``.

    :param min_vouchers: The minimum number of vouchers to place into the
        state, inclusive.

    :param max_vouchers: The maximum number of vouchers to place into the
        state, inclusive.
    """
    # Pick a number of vouchers to build and a number of tokens for them each
    # to have.
    num_vouchers_and_tokens_strategy = tuples(
        integers(min_value=min_vouchers, max_value=max_vouchers),
        integers(min_value=1, max_value=128),
    )

    def build_vouchers_and_tokens(
        num_vouchers_and_tokens: tuple[int, int]
    ) -> SearchStrategy[tuple[list[bytes], list[RandomToken]]]:
        num_vouchers, tokens_per_voucher = num_vouchers_and_tokens
        # Now build enough tokens to spread across all of the vouchers.
        tokens = lists(
            random_tokens(),
            # Generate a simple multiple so each voucher can have the same
            # number which is pretty realistic.
            min_size=num_vouchers * tokens_per_voucher,
            max_size=num_vouchers * tokens_per_voucher,
            unique=True,
        )
        # And the voucher strings themselves.
        vouchers_strategy = lists(
            vouchers(),
            min_size=num_vouchers,
            max_size=num_vouchers,
            unique=True,
        )
        # Pass them both onwards.
        return tuples(vouchers_strategy, tokens)

    vouchers_and_tokens = num_vouchers_and_tokens_strategy.flatmap(
        build_vouchers_and_tokens
    )

    def build_voucher_inserts(
        vouchers_and_tokens: tuple[list[bytes], list[RandomToken]]
    ) -> SearchStrategy[tuple[_VoucherInsert, ...]]:
        vouchers, tokens = vouchers_and_tokens
        tokens_per_voucher = len(tokens) // len(vouchers)

        voucher_strategies = []
        for n, v in enumerate(vouchers):
            voucher_strategies.append(
                builds(
                    _VoucherInsert,
                    voucher=just(v),
                    expected_tokens=integers(
                        min_value=tokens_per_voucher, max_value=tokens_per_voucher * 2
                    ),
                    counter=integers(min_value=0, max_value=15),
                    tokens=just(
                        tokens[n * tokens_per_voucher : (n + 1) * tokens_per_voucher]
                    ),
                )
            )

        return tuples(*voucher_strategies)

    voucher_inserts = vouchers_and_tokens.flatmap(build_voucher_inserts)

    return builds(
        ExistingState,
        vouchers=voucher_inserts,
    )


def sql_identifiers() -> SearchStrategy[str]:
    """
    Build strings suitable for use as SQLite3 identifiers.
    """
    return text(
        min_size=1,
        alphabet=characters(
            # Control characters are largely illegal.
            # Names are case insensitive so don't even generate uppercase.
            blacklist_categories=("Cs", "Lu"),
            # Maybe ] should be allowed but I don't know how to quote it.  '
            # certainly should be but Python sqlite3 module has lots of
            # problems with it.
            # ; is disallowed because sqlparse can't parse statements using it
            # in an identifier.
            blacklist_characters=("\x00", "]", "'", ";"),
        ),
    )


def tables() -> SearchStrategy[Table]:
    """
    Build objects describing tables in a SQLite3 database.
    """

    def first(x: tuple[str, Column]) -> str:
        return x[0]

    return builds(
        Table,
        columns=lists(
            tuples(
                sql_identifiers(),
                builds(Column, affinity=sampled_from(StorageAffinity)),
            ),
            min_size=1,
            unique_by=first,
        ),
    )


def sql_schemas(
    dict_kwargs: Optional[dict[Any, Any]] = None
) -> SearchStrategy[dict[str, Table]]:
    """
    Build objects describing multiple tables in a SQLite3 database.
    """
    if dict_kwargs is None:
        dict_kwargs = {}
    return dictionaries(keys=sql_identifiers(), values=tables(), **dict_kwargs)


# Python has unbounded integers but SQLite3 integers must fall into this
# range.
_sql_integer = integers(min_value=-(2**63) + 1, max_value=2**63 - 1)

# SQLite3 can do infinity and NaN but I don't know how to get them through the
# Python interface.
#
# https://www.sqlite.org/floatingpoint.html
_sql_floats = floats(allow_infinity=False, allow_nan=False, width=64)

# Exclude surrogates because SQLite3 uses UTF-8 and we don't need them.  Also
# they have to come in correctly formed pairs to be legal anyway and it's
# inconvenient to do that with text.
#
# Exclude nul characters because SQLite3 only sort of supports them.  You may
# insert nul characters but don't expect to be able to read them or anything
# following them back.
# https://sqlite.org/nulinstr.html
_sql_text = text(
    alphabet=characters(blacklist_categories=["Cs"], blacklist_characters=["\0"])
)

# Here's how you can build values that match certain storage type affinities.
# SQLite3 will actually allow us to store values of any type in any column but
# it might coerce certain values based on the column affinity.  This means,
# for example, that inserting the string "0" into an INT affinity column will
# result in the integer 0 coming out later.  If we allowed such values to be
# generated it would be very much harder to determine, in general, that values
# are being handled correctly.  It would probably eventually be desirable to
# exercise such cases but I'm not very worried about them since that logic is
# all very well tested inside SQLite3 itself.
_storage_affinity_strategies = {
    StorageAffinity.INT: _sql_integer,
    StorageAffinity.TEXT: one_of(_sql_text, aware_datetimes()),
    StorageAffinity.BLOB: binary(),
    StorageAffinity.REAL: _sql_floats,
    StorageAffinity.NUMERIC: one_of(_sql_integer, _sql_floats),
}


def sql_values() -> SearchStrategy[SQLType]:
    """
    Build values which can be used as arguments in SQL statements.
    """
    return one_of(
        _sql_integer,
        _sql_floats,
        _sql_text,
        binary(),
        aware_datetimes(),
        none(),
    )


def inserts(name: str, table: Table) -> SearchStrategy[Insert]:
    """
    Build objects describing row insertions into the given table.
    """
    return builds(
        partial(Insert, table_name=name, table=table),
        fields=tuples(
            *(
                _storage_affinity_strategies[column.affinity]
                for (_, column) in table.columns
            )
        ),
    )


def updates(name: str, table: Table) -> SearchStrategy[Update]:
    """
    Build objects describing row updates in the given table.
    """
    return builds(
        partial(Update, table_name=name, table=table),
        fields=tuples(
            *(
                _storage_affinity_strategies[column.affinity]
                for (_, column) in table.columns
            )
        ),
    )


def selects(name: str) -> SearchStrategy[Select]:
    """
    Build objects describing SELECT statements on the given table.
    """
    return just(Select(table_name=name))


def deletes(name: str, table: Table) -> SearchStrategy[Delete]:
    """
    Build objects describing row deletions from the given table.
    """
    return just(Delete(table_name=name))


T = TypeVar("T")


def mutations() -> SearchStrategy[Statement]:
    """
    Build statements that make changes to data.
    """

    def make(
        x: tuple[Callable[[str, Table], SearchStrategy[Statement]], str, Table]
    ) -> SearchStrategy[Statement]:
        return x[0](x[1], x[2])

    stmts: SearchStrategy[Callable[[str, Table], SearchStrategy[Statement]]]
    stmts = sampled_from([inserts, deletes, updates])
    return tuples(
        stmts,
        sql_identifiers(),
        tables(),
    ).flatmap(
        make,
    )
