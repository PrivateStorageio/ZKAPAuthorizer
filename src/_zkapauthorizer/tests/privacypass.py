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
Ristretto-flavored PrivacyPass helpers for the test suite.
"""

from challenge_bypass_ristretto import BatchDLEQProof, PublicKey

from ..model import Pass


def make_passes(signing_key, for_message, random_tokens):
    """
    Create a number of cryptographically correct privacy passes.

    :param challenge_bypass_ristretto.SigningKey signing_key: The key to use
        to sign the passes.

    :param bytes for_message: The request-binding message with which to
        associate the passes.

    :param list[challenge_bypass_ristretto.RandomToken] random_tokens: The
        random tokens to feed in to the pass generation process.

    :return list[Pass]: The privacy passes.  The returned list has one
        element for each element of ``random_tokens``.
    """
    blinded_tokens = list(token.blind() for token in random_tokens)
    signatures = list(
        signing_key.sign(blinded_token) for blinded_token in blinded_tokens
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
        unblinded_signature.preimage() for unblinded_signature in unblinded_signatures
    )
    verification_keys = list(
        unblinded_signature.derive_verification_key_sha512()
        for unblinded_signature in unblinded_signatures
    )
    message_signatures = list(
        verification_key.sign_sha512(for_message)
        for verification_key in verification_keys
    )
    passes = list(
        Pass(
            preimage.encode_base64(),
            signature.encode_base64(),
        )
        for (preimage, signature) in zip(preimages, message_signatures)
    )
    return passes
