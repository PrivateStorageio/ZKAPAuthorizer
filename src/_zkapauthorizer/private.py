# -*- coding: utf-8 -*-
# Tahoe-LAFS -- secure, distributed storage grid
#
# Copyright © 2020 The Tahoe-LAFS Software Foundation
#
# Copyright 2019 PrivateStorage.io, LLC

"""
Support code for applying token-based HTTP authorization rules to a
Twisted Web resource hierarchy.
"""

from typing import Callable, TypeVar, Type, Literal, Union
from zope.interface import Interface
from zope.interface.interface import InterfaceClass

# https://github.com/twisted/nevow/issues/106 may affect this code but if so
# then the hotfix Tahoe-LAFS applies should deal with it.
#
# We want to avoid depending on the Tahoe-LAFS Python API since it isn't
# public but we do want to make sure that hotfix is applied.  This seems like
# an alright compromise.
import allmydata.web.private as awp
import attr
from attrs import define, frozen
from cryptography.hazmat.primitives.constant_time import bytes_eq
from twisted.cred.checkers import ANONYMOUS
from twisted.cred.credentials import ICredentials
from twisted.cred.error import UnauthorizedLogin
from twisted.cred.portal import IRealm, Portal
from twisted.internet.defer import fail, succeed, Deferred
from twisted.python.failure import Failure
from twisted.web.guard import HTTPAuthSessionWrapper
from twisted.web.iweb import ICredentialFactory, IRequest
from twisted.web.resource import IResource
from zope.interface import implementer

del awp

SCHEME = b"tahoe-lafs"


AvatarId = Union[bytes, tuple[()]]


class IToken(ICredentials):
    def equals(auth_token: bytes) -> bool:
        pass


@implementer(IToken)
@frozen
class Token(object):
    proposed_token: bytes

    def equals(self, valid_token: bytes) -> bool:
        return bytes_eq(
            valid_token,
            self.proposed_token,
        )


@frozen
class TokenChecker(object):
    get_auth_token: Callable[[], bytes]

    credentialInterfaces = [IToken]

    def requestAvatarId(self, credentials: Token) -> Deferred[AvatarId]:
        required_token = self.get_auth_token()
        if credentials.equals(required_token):
            return succeed(ANONYMOUS)
        return fail(Failure(UnauthorizedLogin())) # type: ignore[no-untyped-call]


@implementer(ICredentialFactory)
@attr.s
class TokenCredentialFactory(object):
    scheme = SCHEME
    authentication_realm = b"tahoe-lafs"

    def getChallenge(self, request: IRequest) -> dict[bytes, bytes]:
        return {b"realm": self.authentication_realm}

    def decode(self, response: bytes, request: IRequest) -> Token:
        return Token(response)

@implementer(IRealm)
@define
class PrivateRealm(object):
    _root: IResource

    def _logout(self) -> None:
        pass

    def requestAvatar(self, avatarId: str, mind: object, *interfaces: InterfaceClass) -> tuple[InterfaceClass, IResource, Callable[[], None]]:
        if IResource in interfaces:
            return (IResource, self._root, self._logout)
        raise NotImplementedError(
            "PrivateRealm supports IResource not {}".format(interfaces),
        )


def _create_private_tree(get_auth_token: Callable[[], bytes], vulnerable: IResource) -> HTTPAuthSessionWrapper:
    realm = PrivateRealm(vulnerable)
    checker = TokenChecker(get_auth_token)
    portal = Portal(realm, [checker]) # type: ignore[no-untyped-call]
    credentials = TokenCredentialFactory()
    return HTTPAuthSessionWrapper(portal, [credentials]) # type: ignore[no-untyped-call]


def create_private_tree(get_auth_token: Callable[[], bytes], vulnerable_tree: IResource) -> HTTPAuthSessionWrapper:
    """
    Create a new resource tree that only allows requests if they include a
    correct `Authorization: tahoe-lafs <api_auth_token>` header (where
    `api_auth_token` matches the private configuration value).

    :param get_auth_token: Get the valid authorization token.

    :param vulnerable_tree: Create the resource hierarchy which will be
        protected by the authorization mechanism.
    """
    return _create_private_tree(
        get_auth_token,
        vulnerable_tree,
    )
