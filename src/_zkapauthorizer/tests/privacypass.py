from __future__ import (
    absolute_import,
)

from privacypass import (
    BatchDLEQProof,
    PublicKey,
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
