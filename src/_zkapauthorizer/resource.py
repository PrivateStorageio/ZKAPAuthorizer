# -*- coding: utf-8 -*-
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
This module implements views (in the MVC sense) for the web interface for
the client side of the storage plugin.  This interface allows users to redeem
vouchers for fresh tokens.

In the future it should also allow users to read statistics about token usage.
"""

from collections.abc import Awaitable
from functools import partial
from json import dumps
from typing import Callable, Optional, Union, cast

from attr import Factory, define, field
from autobahn.twisted.resource import WebSocketResource
from autobahn.twisted.websocket import WebSocketServerFactory, WebSocketServerProtocol
from autobahn.websocket.interfaces import IWebSocketClientAgent
from hyperlink import DecodedURL
from tahoe_capabilities import (
    DirectoryReadCapability,
    danger_real_capability_string,
    readonly_directory_from_string,
)
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IReactorTime
from twisted.logger import Logger
from twisted.python.failure import Failure
from twisted.web.http import BAD_REQUEST, CONFLICT, CREATED, INTERNAL_SERVER_ERROR
from twisted.web.iweb import IRequest
from twisted.web.resource import ErrorPage, IResource, NoResource, Resource
from twisted.web.server import NOT_DONE_YET
from zope.interface import Attribute

from . import NAME
from . import __version__ as _zkapauthorizer_version
from ._base64 import urlsafe_b64decode
from ._json import dumps_utf8, loads
from ._types import JSON
from .config import Config
from .controller import IRedeemer, PaymentController, get_redeemer
from .lease_maintenance import LeaseMaintenanceConfig
from .model import Voucher, VoucherStore
from .pricecalculator import PriceCalculator
from .private import create_private_tree
from .recover import Downloader, RecoveryStages, RecoveryState, StatefulRecoverer
from .replicate import ReplicationAlreadySetup
from .storage_common import (
    get_configured_allowed_public_keys,
    get_configured_pass_value,
    get_configured_shares_needed,
    get_configured_shares_total,
)

# The number of tokens to submit with a voucher redemption.
NUM_TOKENS = 2**15


class IZKAPRoot(IResource):
    """
    The root of the resource tree of this plugin's client web presence.
    """

    store = Attribute("The ``VoucherStore`` used by this resource tree.")
    controller = Attribute("The ``PaymentController`` used by this resource tree.")


def get_token_count(
    plugin_name: str,
    node_config: Config,
) -> int:
    """
    Retrieve the configured voucher value, in number of tokens, from the given
    configuration.

    :param plugin_name: The plugin name to use to choose a configuration
        section.

    :param node_config: See ``from_configuration``.

    :return: The number of tokens from the configuration or a default.
    """
    section_name = "storageclient.plugins.{}".format(plugin_name)
    return int(
        node_config.get_config(
            section=section_name,
            option="default-token-count",
            default=NUM_TOKENS,
        )
    )


def from_configuration(
    node_config: Config,
    store: VoucherStore,
    get_downloader: Callable[[DirectoryReadCapability], Downloader],
    setup_replication: Callable[[], Awaitable[DirectoryReadCapability]],
    redeemer: Optional[IRedeemer] = None,
    clock: Optional[IReactorTime] = None,
) -> IZKAPRoot:
    """
    Instantiate the plugin root resource using data from its configuration
    section, **storageclient.plugins.privatestorageio-zkapauthz-v2**, in the
    Tahoe-LAFS configuration file.  See the configuration documentation for
    details of the configuration section.

    :param node_config: An object representing the overall node configuration.
        The plugin configuration can be extracted from this.  This is also
        used to read and write files in the private storage area of the node's
        persistent state location.

    :param store: The store to use.

    :param redeemer: The voucher redeemer to use.  If ``None`` a sensible one
        is constructed.

    :param clock: See ``PaymentController._clock``.

    :return: The root of the resource hierarchy presented by the client side
        of the plugin.
    """
    if redeemer is None:
        redeemer = get_redeemer(
            NAME,
            node_config,
            None,
            None,
        )
    if clock is None:
        from twisted.internet import reactor

        clock_ = cast(IReactorTime, reactor)
    else:
        clock_ = clock

    default_token_count = get_token_count(
        NAME,
        node_config,
    )
    public_keys = get_configured_allowed_public_keys(node_config)

    controller = PaymentController(
        clock_,
        store,
        redeemer,
        default_token_count,
        public_keys,
    )

    calculator = PriceCalculator(
        get_configured_shares_needed(node_config),
        get_configured_shares_total(node_config),
        get_configured_pass_value(node_config),
    )
    calculate_price = _CalculatePrice(
        calculator,
        LeaseMaintenanceConfig.from_node_config(node_config).get_lease_duration(),
    )

    def get_api_auth_token() -> bytes:
        token = node_config.get_private_config("api_auth_token")
        assert isinstance(token, str)
        return token.encode("utf-8")

    root = cast(
        IZKAPRoot,
        create_private_tree(
            get_api_auth_token,
            authorizationless_resource_tree(
                store,
                controller,
                get_downloader,
                setup_replication,
                calculate_price,
            ),
        ),
    )
    root.store = store
    root.controller = controller
    return root


def set_response_code(request: IRequest, code: int) -> None:
    request.setResponseCode(code)  # type: ignore[no-untyped-call]


def internal_server_error(err: Failure, logger: Logger, request: IRequest) -> None:
    """
    Log a failure and return it as an internal server error for the given
    request.

    This is suitable for use as a last-resort errback while handling a
    request.
    """
    logger.failure("replication setup failed", err)
    set_response_code(request, INTERNAL_SERVER_ERROR)
    request.write(dumps_utf8({"reason": err.getErrorMessage()}))  # type: ignore[no-untyped-call]
    request.finish()  # type: ignore[no-untyped-call]


@define
class ReplicateResource(Resource):
    """
    Integrate the replication configuration implementation with the HTTP
    interface.

    :ivar _setup: The callable the resource will use to do the actual setup
        work.
    """

    _setup: Callable[[], Awaitable[DirectoryReadCapability]]

    _log: Logger = Logger()

    def __attrs_post_init__(self) -> None:
        Resource.__init__(self)  # type: ignore[no-untyped-call]

    def render_POST(self, request: IRequest) -> int:
        d = Deferred.fromCoroutine(self._setup_replication(request))
        d.addErrback(internal_server_error, self._log, request)
        return NOT_DONE_YET

    async def _setup_replication(self, request: IRequest) -> None:
        """
        Call the replication setup function and asynchronously deliver its result
        as a response to the given request.
        """
        try:
            cap_obj = await self._setup()
        except ReplicationAlreadySetup as e:
            status = CONFLICT
            cap_obj = readonly_directory_from_string(e.cap_str)
        else:
            status = CREATED

        application_json(request)
        set_response_code(request, status)
        request.write(  # type: ignore[no-untyped-call]
            dumps_utf8(
                {
                    "recovery-capability": danger_real_capability_string(cap_obj),
                }
            )
        )
        request.finish()  # type: ignore[no-untyped-call]


class RecoverProtocol(WebSocketServerProtocol):  # type: ignore[misc]
    """
    Speaks the server side of the WebSocket /recover protocol.

    A client connects to this to start recovery, sending an opening
    message with the rquired capability.

    As recovery is ongoing, the server sends status updates as they
    become available.

    When the recovery is finished, and final message is sent
    (indicating overall success or failure) and the WebSocket is
    closed.
    """

    _log = Logger()

    def onClose(self, wasClean: object, code: object, reason: object) -> None:
        """
        WebSocket API: we've lost our connection for some reason
        """
        try:
            self.factory.clients.remove(self)
        except ValueError:
            # may not have initiated recovery yet so it might not be
            # in the clients list
            pass

    def onMessage(self, payload: bytes, isBinary: bool) -> None:
        """
        WebSocket API: a message has been received from the client (the
        only thing they can send is a request to initiate recovery).
        """
        try:
            body = loads(payload)
            if not isinstance(body, dict):
                raise ValueError(f"Expected dict, instead got {type(body)}")
            if set(body.keys()) != {"recovery-capability"}:
                raise ValueError("Unknown keys present in request")
            cap_str = body["recovery-capability"]
            if not isinstance(cap_str, str):
                raise ValueError(
                    f"Recovery capability must be a string, got {type(cap_str)!r} instead."
                )
            recovery_capability = readonly_directory_from_string(cap_str)
        except Exception:
            self._log.failure("Failed to initiate recovery")
            self.sendClose(
                code=4000,
                reason="Failed to parse recovery request",
            )
            return
        # we have a valid request, tell our factory to start recovery
        self.factory.initiate_recovery(recovery_capability, self)


@define
class RecoverFactory(WebSocketServerFactory):  # type: ignore[misc]
    """
    Track state of recovery.

    In the factory because we want at most one active recovery attempt
    no matter how many clients there are and because something needs
    to link to other resources that are also constructed once.
    """

    protocol = RecoverProtocol
    _log = Logger()

    store: VoucherStore
    get_downloader: Callable[[DirectoryReadCapability], Downloader]
    recoverer: StatefulRecoverer = field()
    recovering_d: Optional[Deferred[None]] = None
    recovering_cap: Optional[DirectoryReadCapability] = None
    # manage WebSocket client(s)
    clients: list[WebSocketServerProtocol] = Factory(list)
    sent_updates: list[bytes] = Factory(list)

    @recoverer.default
    def _default_recoverer(self) -> StatefulRecoverer:
        return StatefulRecoverer(listeners={self._on_state_change})

    def __attrs_post_init__(self) -> None:
        WebSocketServerFactory.__init__(self, server="ZKAPAuthorizer")

    def _on_state_change(self, state: RecoveryState) -> None:
        """
        Whenever the state of recovery changes, update all our clients
        """
        update_msg = dumps(state.marshal()).encode("utf8")
        self.sent_updates.append(update_msg)
        for client in self.clients:
            client.sendMessage(update_msg, False)

    def initiate_recovery(
        self, cap: DirectoryReadCapability, client: WebSocketServerProtocol
    ) -> None:
        """
        A new WebSocket client has asked for recovery.

        If there is no recovery, begin one and send updates to this
        client.

        If a recovery is already started _and_ the capability is the
        same, send updates to this client too.

        Otherwise, error.
        """
        self.clients.append(client)
        if self.recovering_d is None:
            self.recovering_cap = cap
            self.recovering_d = Deferred.fromCoroutine(self._recover(self.store, cap))

            def disconnect_clients() -> None:
                for client in self.clients:
                    client.sendClose()

            def err(f: Failure) -> None:
                self._log.failure("Error during restore", f)
                # One likely reason to get here is the ValueError we
                # raise about existing local state .. and the
                # "recoverer" itself can't really handle this (or
                # other) errors happening before it is called.
                self.recoverer._set_state(
                    RecoveryState(
                        RecoveryStages.import_failed,
                        f.getErrorMessage(),
                    )
                )
                disconnect_clients()

            def happy(_: object) -> None:
                disconnect_clients()

            self.recovering_d.addCallbacks(happy, err)

        elif self.recovering_cap != cap:
            self.sendClose(
                code=4000, reason="Ongoing recovery with different capability"
            )

        else:
            # we got another client, and they sent the same recovery
            # capability, so be idempotent by acting the same as if this
            # was the first client. That means sending this client all the
            # status updates we've sent so far.
            for update in self.sent_updates:
                client.sendMessage(update)

    def buildProtocol(self, addr: object) -> RecoverProtocol:
        """
        IFactory API
        """
        protocol = self.protocol()
        protocol.factory = self
        return protocol

    async def _recover(
        self,
        store: VoucherStore,
        cap: DirectoryReadCapability,
    ) -> None:
        """
        :raises: NotEmpty if there is existing local state
        """
        # If these things succeed then we will have started recovery and
        # generated a response to the request.
        downloader = self.get_downloader(cap)
        await store.call_if_empty(
            partial(self.recoverer.recover, downloader)  # cursor added by call_if_empty
        )
        # let all exceptions (including NotEmpty) out


def authorizationless_resource_tree(
    store: VoucherStore,
    controller: PaymentController,
    get_downloader: Callable[[DirectoryReadCapability], Downloader],
    setup_replication: Callable[[], Awaitable[DirectoryReadCapability]],
    calculate_price: IResource,
) -> Resource:
    """
    Create the full ZKAPAuthorizer client plugin resource hierarchy with no
    authorization applied.

    :param store: The store to use.
    :param controller: The payment controller to use.

    :param get_downloader: A callable which accepts a replica identifier and
        can download the replica data.

    :param calculate_price: The resource for the price calculation endpoint.

    :return IResource: The root of the resource hierarchy.
    """
    root = Resource()  # type: ignore[no-untyped-call]

    root.putChild(
        b"recover",
        WebSocketResource(RecoverFactory(store, get_downloader)),
    )
    root.putChild(
        b"replicate",
        ReplicateResource(setup_replication),
    )
    root.putChild(
        b"voucher",
        _VoucherCollection(
            store,
            controller,
        ),
    )
    root.putChild(
        b"lease-maintenance",
        _LeaseMaintenanceResource(
            store,
            controller,
        ),
    )
    root.putChild(
        b"version",
        _ProjectVersion(),  # type: ignore[no-untyped-call]
    )
    root.putChild(
        b"calculate-price",
        calculate_price,
    )
    return root


class _CalculatePrice(Resource):
    """
    This resource exposes a storage price calculator.
    """

    allowedMethods = [b"POST"]

    render_HEAD = render_GET = None

    def __init__(self, price_calculator: PriceCalculator, lease_period: int):
        """
        :param _PriceCalculator price_calculator: The object which can actually
            calculate storage prices.

        :param lease_period: See ``authorizationless_resource_tree``
        """
        self._price_calculator = price_calculator
        self._lease_period = lease_period
        Resource.__init__(self)  # type: ignore[no-untyped-call]

    def render_POST(self, request: IRequest) -> Union[int, bytes]:
        """
        Calculate the price in ZKAPs to store or continue storing files specified
        sizes.
        """
        if wrong_content_type(request, "application/json"):
            return NOT_DONE_YET

        application_json(request)
        payload = request.content.read()
        try:
            body_object = loads(payload)
        except ValueError:
            set_response_code(request, BAD_REQUEST)
            return dumps_utf8(
                {
                    "error": "could not parse request body",
                }
            )
        if not isinstance(body_object, dict):
            set_response_code(request, BAD_REQUEST)
            return dumps_utf8(
                {
                    "error": "request body must be a JSON object",
                }
            )

        try:
            version = body_object["version"]
            sizes = body_object["sizes"]
        except (TypeError, KeyError):
            set_response_code(request, BAD_REQUEST)
            return dumps_utf8(
                {
                    "error": "could not read `version` and `sizes` properties",
                }
            )

        if version != 1:
            set_response_code(request, BAD_REQUEST)
            return dumps_utf8(
                {
                    "error": "did not find required version number 1 in request",
                }
            )

        if not isinstance(sizes, list) or not all(
            isinstance(size, int) and size >= 0 for size in sizes
        ):
            set_response_code(request, BAD_REQUEST)
            return dumps_utf8(
                {
                    "error": "did not find required positive integer sizes list in request",
                }
            )

        application_json(request)

        price = self._price_calculator.calculate(sizes)
        return dumps_utf8(
            {
                "price": price,
                "period": self._lease_period,
            }
        )


def wrong_content_type(request: IRequest, required_type: str) -> bool:
    """
    Check the content-type of a request and respond if it is incorrect.

    :param request: The request object to check.

    :param str required_type: The required content-type (eg
        ``"application/json"``).

    :return bool: ``True`` if the content-type is wrong and an error response
        has been generated.  ``False`` otherwise.
    """
    actual_type = request.requestHeaders.getRawHeaders(
        "content-type",
        [None],
    )[0]
    if actual_type != required_type:
        set_response_code(request, BAD_REQUEST)
        request.finish()  # type: ignore[no-untyped-call]
        return True
    return False


def application_json(request: IRequest) -> None:
    """
    Set the given request's response content-type to ``application/json``.

    :param request: The request to modify.
    """
    request.responseHeaders.setRawHeaders("content-type", ["application/json"])


class _ProjectVersion(Resource):
    """
    This resource exposes the version of **ZKAPAuthorizer** itself.
    """

    def render_GET(self, request: IRequest) -> bytes:
        application_json(request)
        return dumps_utf8(
            {
                "version": _zkapauthorizer_version,
            }
        )


class _LeaseMaintenanceResource(Resource):
    """
    This class implements inspection of lease maintenance activity.  Users
    **GET** this resource to learn about lease maintenance spending.
    """

    _log = Logger()

    def __init__(self, store: VoucherStore, controller: PaymentController) -> None:
        self._store = store
        self._controller = controller
        Resource.__init__(self)  # type: ignore[no-untyped-call]

    def render_GET(self, request: IRequest) -> bytes:
        """
        Retrieve the spending information.
        """
        application_json(request)
        return dumps_utf8(
            {
                "total": self._store.count_unblinded_tokens(),
                "spending": self._lease_maintenance_activity(),
            }
        )

    def _lease_maintenance_activity(self) -> Optional[dict[str, JSON]]:
        activity = self._store.get_latest_lease_maintenance_activity()
        if activity is None:
            return activity
        return {
            "when": activity.finished.isoformat(),
            "count": activity.passes_required,
        }


class _VoucherCollection(Resource):
    """
    This class implements redemption of vouchers.  Users **PUT** such numbers
    to this resource which delegates redemption responsibilities to the
    redemption controller.  Child resources of this resource can also be
    retrieved to monitor the status of previously submitted vouchers.
    """

    _log = Logger()

    def __init__(self, store: VoucherStore, controller: PaymentController):
        self._store = store
        self._controller = controller
        Resource.__init__(self)  # type: ignore[no-untyped-call]

    def render_PUT(self, request: IRequest) -> bytes:
        """
        Record a voucher and begin attempting to redeem it.
        """
        try:
            payload = loads(request.content.read())
        except Exception:
            return bad_request("json request body required").render(request)  # type: ignore[no-untyped-call,no-any-return]
        if not isinstance(payload, dict):
            return bad_request("request body must be a JSON object").render(request)  # type: ignore[no-untyped-call,no-any-return]
        if payload.keys() != {"voucher"}:
            return bad_request(  # type: ignore[no-any-return]
                "request object must have exactly one key: 'voucher'"
            ).render(
                request
            )  # type: ignore[no-untyped-call]
        voucher = payload["voucher"]
        if not is_syntactic_voucher(voucher):
            return bad_request("submitted voucher is syntactically invalid").render(  # type: ignore[no-untyped-call,no-any-return]
                request
            )

        self._log.info(
            "Accepting a voucher ({voucher}) for redemption.", voucher=voucher
        )
        Deferred.fromCoroutine(self._controller.redeem(voucher.encode("ascii")))
        return b""

    def render_GET(self, request: IRequest) -> bytes:
        application_json(request)
        return dumps_utf8(
            {
                "vouchers": list(
                    self._controller.incorporate_transient_state(voucher).marshal()
                    for voucher in self._store.list()
                ),
            }
        )

    def getChild(self, segment: bytes, request: IRequest) -> IResource:
        voucher_str = segment.decode("utf-8")
        if not is_syntactic_voucher(voucher_str):
            return bad_request()
        try:
            voucher_obj = self._store.get(voucher_str.encode("ascii"))
        except KeyError:
            return NoResource()  # type: ignore[no-untyped-call]
        return VoucherView(self._controller.incorporate_transient_state(voucher_obj))


def is_syntactic_voucher(voucher: str) -> bool:
    """
    :param voucher: A candidate object to inspect.

    :return bool: ``True`` if and only if ``voucher`` is a text string
        containing a syntactically valid voucher.  This says **nothing** about
        the validity of the represented voucher itself.  A ``True`` result
        only means the string can be **interpreted** as a voucher.
    """
    if not isinstance(voucher, str):
        return False
    if len(voucher) != 44:
        # TODO.  44 is the length of 32 bytes base64 encoded.  This model
        # information presumably belongs somewhere else.
        return False
    try:
        urlsafe_b64decode(voucher.encode("ascii"))
    except Exception:
        return False
    return True


class VoucherView(Resource):
    """
    This class implements a view for a ``Voucher`` instance.
    """

    def __init__(self, voucher: Voucher) -> None:
        """
        :param Voucher reference: The model object for which to provide a
            view.
        """
        self._voucher = voucher
        Resource.__init__(self)  # type: ignore[no-untyped-call]

    def render_GET(self, request: IRequest) -> bytes:
        application_json(request)
        return self._voucher.to_json()


def bad_request(reason: str = "Bad Request") -> IResource:
    """
    :return: A resource which can be rendered to produce a **BAD REQUEST**
        response.
    """
    return ErrorPage(  # type: ignore[no-untyped-call]
        BAD_REQUEST,
        b"Bad Request",
        reason.encode("utf-8"),
    )


async def recover(
    agent: IWebSocketClientAgent,
    api_root: DecodedURL,
    auth_token: str,
    replica_dircap: DirectoryReadCapability,
) -> list[JSON]:
    """
    Initiate recovery from a replica.

    :return: The status updates received while recovery was progressing.
    """
    endpoint_url = api_root.child(
        "storage-plugins", "privatestorageio-zkapauthz-v2", "recover"
    ).to_text()
    proto = await agent.open(
        endpoint_url,
        {"headers": {"Authorization": f"tahoe-lafs {auth_token}"}},
    )
    updates = []
    proto.on("message", lambda msg, is_binary: updates.append(loads(msg)))
    await proto.is_open
    proto.sendMessage(
        dumps_utf8(
            {
                "recovery-capability": danger_real_capability_string(replica_dircap),
            }
        ),
    )
    await proto.is_closed
    return updates
