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
    urlsafe_b64encode,
)

import attr

from hypothesis.strategies import (
    one_of,
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
)

from twisted.web.test.requesthelper import (
    DummyRequest,
)

from allmydata.interfaces import (
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
    Redeemed,
)


def _merge_dictionaries(dictionaries):
    result = {}
    for d in dictionaries:
        result.update(d)
    return result


def _tahoe_config_quote(text):
    return text.replace(u"%", u"%%")


def _config_string_from_sections(divided_sections):
    sections = _merge_dictionaries(divided_sections)
    return u"".join(list(
        u"[{name}]\n{items}\n".format(
            name=name,
            items=u"\n".join(
                u"{key} = {value}".format(key=key, value=_tahoe_config_quote(value))
                for (key, value)
                in contents.items()
            )
        )
        for (name, contents) in sections.items()
    ))


def tahoe_config_texts(storage_client_plugins):
    """
    Build the text of complete Tahoe-LAFS configurations for a node.
    """
    return builds(
        lambda *sections: _config_string_from_sections(
            sections,
        ),
        fixed_dictionaries(
            {
                "storageclient.plugins.{}".format(name): configs
                for (name, configs)
                in storage_client_plugins.items()
            },
        ),
        fixed_dictionaries(
            {
                "node": fixed_dictionaries(
                    {
                        "nickname": node_nicknames(),
                    },
                ),
                "client": fixed_dictionaries(
                    {
                        "storage.plugins": just(
                            u",".join(storage_client_plugins.keys()),
                        ),
                    },
                ),
            },
        ),
    )


def minimal_tahoe_configs(storage_client_plugins=None):
    """
    Build complete Tahoe-LAFS configurations for a node.
    """
    if storage_client_plugins is None:
        storage_client_plugins = {}
    return tahoe_config_texts(
        storage_client_plugins,
    ).map(
        lambda config_text: lambda basedir, portnumfile: config_from_string(
            basedir,
            portnumfile,
            config_text.encode("utf-8"),
        ),
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


def server_configurations(signing_key_path):
    """
    Build configuration values for the server-side plugin.

    :param unicode signing_key_path: A value to insert for the
        **ristretto-signing-key-path** item.
    """
    return just({
        u"ristretto-issuer-root-url": u"https://issuer.example.invalid/",
        u"ristretto-signing-key-path": signing_key_path.path,
    })


def client_ristrettoredeemer_configurations():
    """
    Build Ristretto-using configuration values for the client-side plugin.
    """
    return just({
        u"ristretto-issuer-root-url": u"https://issuer.example.invalid/",
        u"redeemer": u"ristretto",
    })


def client_dummyredeemer_configurations():
    """
    Build DummyRedeemer-using configuration values for the client-side plugin.
    """
    return just({
        u"redeemer": u"dummy",
    })


def client_doublespendredeemer_configurations():
    """
    Build DummyRedeemer-using configuration values for the client-side plugin.
    """
    return just({
        u"redeemer": u"double-spend",
    })


def client_nonredeemer_configurations():
    """
    Build NonRedeemer-using configuration values for the client-side plugin.
    """
    return just({
        u"redeemer": u"non",
    })


def tahoe_configs(zkapauthz_v1_configuration=client_dummyredeemer_configurations()):
    """
    Build complete Tahoe-LAFS configurations including the zkapauthorizer
    client plugin section.
    """
    return minimal_tahoe_configs({
        u"privatestorageio-zkapauthz-v1": zkapauthz_v1_configuration,
    })


def vouchers():
    """
    Build unicode strings in the format of vouchers.
    """
    return binary(
        min_size=32,
        max_size=32,
    ).map(
        urlsafe_b64encode,
    ).map(
        lambda voucher: voucher.decode("ascii"),
    )


def voucher_states():
    """
    Build unicode strings giving states a Voucher can be in.
    """
    return one_of(
        just(Pending()),
        builds(
            DoubleSpend,
            finished=datetimes(),
        ),
        builds(
            Redeemed,
            finished=datetimes(),
            token_count=one_of(integers(min_value=1)),
        ),
    )


def voucher_objects():
    """
    Build ``Voucher`` instances.
    """
    return builds(
        Voucher,
        number=vouchers(),
        created=one_of(none(), datetimes()),
        state=voucher_states(),
    )


def random_tokens():
    """
    Build random tokens as unicode strings.
    """
    return binary(
        min_size=32,
        max_size=32,
    ).map(
        urlsafe_b64encode,
    ).map(
        lambda token: RandomToken(token.decode("ascii")),
    )


def zkaps():
    """
    Build random ZKAPs as ``Pass` instances.
    """
    return builds(
        lambda preimage, signature: Pass(u"{} {}".format(preimage, signature)),
        # Sizes informed by
        # https://github.com/brave-intl/challenge-bypass-ristretto/blob/2f98b057d7f353c12b2b12d0f5ae9ad115f1d0ba/src/oprf.rs#L18-L33
        preimage=binary(min_size=64, max_size=64).map(urlsafe_b64encode),
        signature=binary(min_size=64, max_size=64).map(urlsafe_b64encode),
    )


def unblinded_tokens():
    """
    Builds random ``_zkapauthorizer.model.UnblindedToken`` wrapping invalid
    base64 encode data.  You cannot use these in the PrivacyPass cryptographic
    protocol but you can put them into the database and take them out again.
    """
    return binary(
        min_size=32,
        max_size=32,
    ).map(
        urlsafe_b64encode,
    ).map(
        lambda zkap: UnblindedToken(zkap.decode("ascii")),
    )


def request_paths():
    """
    Build lists of unicode strings that represent the path component of an
    HTTP request.

    :see: ``requests``
    """


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


def sizes():
    """
    Build Tahoe-LAFS share sizes.
    """
    return integers(
        # Size 0 data isn't data, it's nothing.
        min_value=1,
        # For the moment there are some assumptions in the test suite that
        # limit us to an amount of storage that can be paid for with one ZKAP.
        # That will be fixed eventually.  For now, keep the sizes pretty low.
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
        max_size=4,
    )


def announcements():
    """
    Build announcements for the ZKAPAuthorizer plugin.
    """
    return just({
        u"ristretto-issuer-root-url": u"https://issuer.example.invalid/",
    })
