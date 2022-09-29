from typing import Mapping, Any

from attrs import define, frozen
from challenge_bypass_ristretto import BatchDLEQProof, PublicKey, SigningKey
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IListeningPort, IReactorTCP
from twisted.python.filepath import FilePath
from twisted.web.resource import Resource
from twisted.web.server import Site

from .. import NAME
from .._json import dumps_utf8 as dumps
from .._json import loads


@define
class Issuer:
    port: IListeningPort
    signing_key_path: FilePath

    # testresources jams crap onto us
    issuer_dir: Any = None

    @property
    def allowed_public_keys(self) -> list[PublicKey]:
        return [PublicKey.from_signing_key(
            SigningKey.decode_base64(self.signing_key_path.getContent())
        )]

    @property
    def encoded_allowed_public_keys(self) -> str:
        return ",".join(k.encode_base64().decode("ascii") for k in self.allowed_public_keys)

    @property
    def root_url(self) -> str:
        return f"http://127.0.0.1:{self.port.getHost().port}/"

    @property
    def server_config(self) -> Mapping[str, str]:
        return {
            "ristretto-issuer-root-url": self.root_url,
            "ristretto-signing-key-path": self.signing_key_path.path,
        }

    @property
    def client_config(self) -> Mapping[str, str]:
        return {
            "redeemer": "ristretto",
            "ristretto-issuer-root-url": self.root_url,
            "allowed-public-keys": self.encoded_allowed_public_keys,
        }


@define
class Redeem(Resource):
    signing_key: SigningKey

    def render_POST(self, request):
        blinded_tokens = loads(request.content.read())["redeemTokens"]
        signatures = list(
            self.signing_key.sign(blinded_token) for blinded_token in blinded_tokens
        )
        proof = BatchDLEQProof.create(
            self.signing_key,
            blinded_tokens,
            signatures,
        )
        return dumps(
            {
                "success": True,
                "signatures": [sig.encode_base64() for sig in signatures],
                "proof": proof.encode_base64(),
            }
        )


def issuer(signing_key: SigningKey) -> Site:
    v1 = Resource()
    v1.putChild("redeem", Redeem(signing_key))

    r = Resource()
    r.putChild("v1", v1)

    return Site(r)


def run_issuer(reactor: IReactorTCP, signing_key_path: FilePath) -> Issuer:
    signing_key = SigningKey.decode_base64(signing_key_path.getContent())
    port = reactor.listenTCP(0, Site(issuer(signing_key)), interface="127.0.0.1")
    return Issuer(port, signing_key_path)


def stop_issuer(issuer: Issuer) -> Deferred[None]:
    return issuer.port.stopListening()
