from __future__ import (
    absolute_import,
)

from random import (
    shuffle,
)
from testtools import (
    TestCase,
)
from testtools.matchers import (
    Equals,
    AfterPreprocessing,
)
from hypothesis import (
    given,
)
from hypothesis.strategies import (
    integers,
    lists,
)
from privacypass import (
    BatchDLEQProof,
    PublicKey,
    RandomToken,
    random_signing_key,
)

from .strategies import (
    zkaps,
)
from .fixtures import (
    AnonymousStorageServer,
)
from ..api import (
    ZKAPAuthorizerStorageServer,
)


def make_passes(signing_key, for_message, random_tokens):
    blinded_tokens = list(
        token.blind()
        for token
        in random_tokens
    )
    signatures = list(
        signing_key.sign(blinded_token)
        for blinded_token
        in blinded_tokens
    )
    proof = BatchDLEQProof.create(
        signing_key,
        blinded_tokens,
        signatures,
    )
    unblinded_signatures = proof.invalid_or_unblind(
        random_tokens,
        blinded_tokens,
        signatures,
        PublicKey.from_signing_key(signing_key),
    )
    preimages = list(
        unblinded_signature.preimage()
        for unblinded_signature
        in unblinded_signatures
    )
    verification_keys = list(
        unblinded_signature.derive_verification_key_sha512()
        for unblinded_signature
        in unblinded_signatures
    )
    message_signatures = list(
        verification_key.sign_sha512(for_message.encode("utf-8"))
        for verification_key
        in verification_keys
    )
    passes = list(
        u"{} {}".format(
            preimage.encode_base64().decode("ascii"),
            signature.encode_base64().decode("ascii"),
        ).encode("ascii")
        for (preimage, signature)
        in zip(preimages, message_signatures)
    )
    return passes



class PassValidationTests(TestCase):
    """
    Tests for pass validation performed by ``ZKAPAuthorizerStorageServer``.
    """
    def setUp(self):
        super(PassValidationTests, self).setUp()
        self.anonymous_storage_server = self.useFixture(AnonymousStorageServer()).storage_server
        self.signing_key = random_signing_key()
        self.storage_server = ZKAPAuthorizerStorageServer(
            self.anonymous_storage_server,
            self.signing_key,
        )

    @given(integers(min_value=0, max_value=64), lists(zkaps(), max_size=64))
    def test_validation_result(self, valid_count, invalid_passes):
        """
        ``_get_valid_passes`` returns the number of cryptographically valid passes
        in the list passed to it.
        """
        message = u"hello world"
        valid_passes = make_passes(
            self.signing_key,
            message,
            list(RandomToken.create() for i in range(valid_count)),
        )
        all_passes = valid_passes + list(pass_.text.encode("ascii") for pass_ in invalid_passes)
        shuffle(all_passes)

        self.assertThat(
            self.storage_server._validate_passes(message, all_passes),
            AfterPreprocessing(
                set,
                Equals(set(valid_passes)),
            ),
        )
