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

from sys import (
    maxint,
)
from itertools import (
    islice,
)
from json import (
    loads,
    load,
    dumps,
)
from zope.interface import (
    Attribute,
)
from twisted.logger import (
    Logger,
)
from twisted.web.http import (
    BAD_REQUEST,
)
from twisted.web.server import (
    NOT_DONE_YET,
)
from twisted.web.resource import (
    IResource,
    ErrorPage,
    NoResource,
    Resource,
)

from . import (
    __version__ as _zkapauthorizer_version,
)

from ._base64 import (
    urlsafe_b64decode,
)

from .storage_common import (
    get_configured_shares_needed,
    get_configured_shares_total,
    get_configured_pass_value,
    get_configured_lease_duration,
    get_configured_allowed_public_keys,
)

from .pricecalculator import (
    PriceCalculator,
)

from .controller import (
    PaymentController,
    get_redeemer,
)

from .private import (
    create_private_tree,
)

# The number of tokens to submit with a voucher redemption.
NUM_TOKENS = 2 ** 15


class IZKAPRoot(IResource):
    """
    The root of the resource tree of this plugin's client web presence.
    """

    store = Attribute("The ``VoucherStore`` used by this resource tree.")
    controller = Attribute("The ``PaymentController`` used by this resource tree.")


def get_token_count(
    plugin_name,
    node_config,
):
    """
    Retrieve the configured voucher value, in number of tokens, from the given
    configuration.

    :param unicode plugin_name: The plugin name to use to choose a
        configuration section.

    :param _Config node_config: See ``from_configuration``.

    :param int default: The value to return if none is configured.
    """
    section_name = u"storageclient.plugins.{}".format(plugin_name)
    return int(
        node_config.get_config(
            section=section_name,
            option=u"default-token-count",
            default=NUM_TOKENS,
        )
    )


def from_configuration(
    node_config,
    store,
    redeemer=None,
    clock=None,
):
    """
    Instantiate the plugin root resource using data from its configuration
    section, **storageclient.plugins.privatestorageio-zkapauthz-v1**, in the
    Tahoe-LAFS configuration file.  See the configuration documentation for
    details of the configuration section.

    :param _Config node_config: An object representing the overall node
        configuration.  The plugin configuration can be extracted from this.
        This is also used to read and write files in the private storage area
        of the node's persistent state location.

    :param VoucherStore store: The store to use.

    :param IRedeemer redeemer: The voucher redeemer to use.  If ``None`` a
        sensible one is constructed.

    :param clock: See ``PaymentController._clock``.

    :return IZKAPRoot: The root of the resource hierarchy presented by the
        client side of the plugin.
    """
    plugin_name = u"privatestorageio-zkapauthz-v1"
    if redeemer is None:
        redeemer = get_redeemer(
            plugin_name,
            node_config,
            None,
            None,
        )
    default_token_count = get_token_count(
        plugin_name,
        node_config,
    )
    controller = PaymentController(
        store,
        redeemer,
        default_token_count,
        allowed_public_keys=get_configured_allowed_public_keys(node_config),
        clock=clock,
    )

    calculator = PriceCalculator(
        get_configured_shares_needed(node_config),
        get_configured_shares_total(node_config),
        get_configured_pass_value(node_config),
    )
    calculate_price = _CalculatePrice(
        calculator,
        get_configured_lease_duration(node_config),
    )

    root = create_private_tree(
        lambda: node_config.get_private_config(b"api_auth_token"),
        authorizationless_resource_tree(
            store,
            controller,
            calculate_price,
        ),
    )
    root.store = store
    root.controller = controller
    return root


def authorizationless_resource_tree(
    store,
    controller,
    calculate_price,
):
    """
    Create the full ZKAPAuthorizer client plugin resource hierarchy with no
    authorization applied.

    :param VoucherStore store: The store to use.
    :param PaymentController controller: The payment controller to use.

    :param IResource calculate_price: The resource for the price calculation endpoint.

    :return IResource: The root of the resource hierarchy.
    """
    root = Resource()
    root.putChild(
        b"voucher",
        _VoucherCollection(
            store,
            controller,
        ),
    )
    root.putChild(
        b"unblinded-token",
        _UnblindedTokenCollection(
            store,
            controller,
        ),
    )
    root.putChild(
        b"version",
        _ProjectVersion(),
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

    def __init__(self, price_calculator, lease_period):
        """
        :param _PriceCalculator price_calculator: The object which can actually
            calculate storage prices.

        :param lease_period: See ``authorizationless_resource_tree``
        """
        self._price_calculator = price_calculator
        self._lease_period = lease_period
        Resource.__init__(self)

    def render_POST(self, request):
        """
        Calculate the price in ZKAPs to store or continue storing files specified
        sizes.
        """
        if wrong_content_type(request, u"application/json"):
            return NOT_DONE_YET

        application_json(request)
        payload = request.content.read()
        try:
            body_object = loads(payload)
        except ValueError:
            request.setResponseCode(BAD_REQUEST)
            return dumps(
                {
                    "error": "could not parse request body",
                }
            )

        try:
            version = body_object[u"version"]
            sizes = body_object[u"sizes"]
        except (TypeError, KeyError):
            request.setResponseCode(BAD_REQUEST)
            return dumps(
                {
                    "error": "could not read `version` and `sizes` properties",
                }
            )

        if version != 1:
            request.setResponseCode(BAD_REQUEST)
            return dumps(
                {
                    "error": "did not find required version number 1 in request",
                }
            )

        if not isinstance(sizes, list) or not all(
            isinstance(size, (int, long)) and size >= 0 for size in sizes
        ):
            request.setResponseCode(BAD_REQUEST)
            return dumps(
                {
                    "error": "did not find required positive integer sizes list in request",
                }
            )

        application_json(request)

        price = self._price_calculator.calculate(sizes)
        return dumps(
            {
                u"price": price,
                u"period": self._lease_period,
            }
        )


def wrong_content_type(request, required_type):
    """
    Check the content-type of a request and respond if it is incorrect.

    :param request: The request object to check.

    :param unicode required_type: The required content-type (eg
        ``u"application/json"``).

    :return bool: ``True`` if the content-type is wrong and an error response
        has been generated.  ``False`` otherwise.
    """
    actual_type = request.requestHeaders.getRawHeaders(
        u"content-type",
        [None],
    )[0]
    if actual_type != required_type:
        request.setResponseCode(BAD_REQUEST)
        request.finish()
        return True
    return False


def application_json(request):
    """
    Set the given request's response content-type to ``application/json``.

    :param twisted.web.iweb.IRequest request: The request to modify.
    """
    request.responseHeaders.setRawHeaders(u"content-type", [u"application/json"])


class _ProjectVersion(Resource):
    """
    This resource exposes the version of **ZKAPAuthorizer** itself.
    """

    def render_GET(self, request):
        application_json(request)
        return dumps(
            {
                "version": _zkapauthorizer_version,
            }
        )


class _UnblindedTokenCollection(Resource):
    """
    This class implements inspection of unblinded tokens.  Users **GET** this
    resource to find out about unblinded tokens in the system.
    """

    _log = Logger()

    def __init__(self, store, controller):
        self._store = store
        self._controller = controller
        Resource.__init__(self)

    def render_GET(self, request):
        """
        Retrieve some unblinded tokens and associated information.
        """
        application_json(request)
        state = self._store.backup()
        unblinded_tokens = state[u"unblinded-tokens"]

        limit = request.args.get(b"limit", [None])[0]
        if limit is not None:
            limit = min(maxint, int(limit))

        position = request.args.get(b"position", [b""])[0].decode("utf-8")

        return dumps(
            {
                u"total": len(unblinded_tokens),
                u"spendable": self._store.count_unblinded_tokens(),
                u"unblinded-tokens": list(
                    islice(
                        (token for token in unblinded_tokens if token > position), limit
                    )
                ),
                u"lease-maintenance-spending": self._lease_maintenance_activity(),
            }
        )

    def render_POST(self, request):
        """
        Store some unblinded tokens.
        """
        application_json(request)
        unblinded_tokens = load(request.content)[u"unblinded-tokens"]
        self._store.insert_unblinded_tokens(unblinded_tokens, group_id=0)
        return dumps({})

    def _lease_maintenance_activity(self):
        activity = self._store.get_latest_lease_maintenance_activity()
        if activity is None:
            return activity
        return {
            u"when": activity.finished.isoformat(),
            u"count": activity.passes_required,
        }


class _VoucherCollection(Resource):
    """
    This class implements redemption of vouchers.  Users **PUT** such numbers
    to this resource which delegates redemption responsibilities to the
    redemption controller.  Child resources of this resource can also be
    retrieved to monitor the status of previously submitted vouchers.
    """

    _log = Logger()

    def __init__(self, store, controller):
        self._store = store
        self._controller = controller
        Resource.__init__(self)

    def render_PUT(self, request):
        """
        Record a voucher and begin attempting to redeem it.
        """
        try:
            payload = loads(request.content.read())
        except Exception:
            return bad_request(u"json request body required").render(request)
        if payload.keys() != [u"voucher"]:
            return bad_request(
                u"request object must have exactly one key: 'voucher'"
            ).render(request)
        voucher = payload[u"voucher"]
        if not is_syntactic_voucher(voucher):
            return bad_request(u"submitted voucher is syntactically invalid").render(
                request
            )

        self._log.info(
            "Accepting a voucher ({voucher}) for redemption.", voucher=voucher
        )
        self._controller.redeem(voucher)
        return b""

    def render_GET(self, request):
        application_json(request)
        return dumps(
            {
                u"vouchers": list(
                    self._controller.incorporate_transient_state(voucher).marshal()
                    for voucher in self._store.list()
                ),
            }
        )

    def getChild(self, segment, request):
        voucher = segment.decode("utf-8")
        if not is_syntactic_voucher(voucher):
            return bad_request()
        try:
            voucher = self._store.get(voucher)
        except KeyError:
            return NoResource()
        return VoucherView(self._controller.incorporate_transient_state(voucher))


def is_syntactic_voucher(voucher):
    """
    :param voucher: A candidate object to inspect.

    :return bool: ``True`` if and only if ``voucher`` is a unicode string
        containing a syntactically valid voucher.  This says **nothing** about
        the validity of the represented voucher itself.  A ``True`` result
        only means the unicode string can be **interpreted** as a voucher.
    """
    if not isinstance(voucher, unicode):
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

    def __init__(self, voucher):
        """
        :param Voucher reference: The model object for which to provide a
            view.
        """
        self._voucher = voucher
        Resource.__init__(self)

    def render_GET(self, request):
        application_json(request)
        return self._voucher.to_json()


def bad_request(reason=u"Bad Request"):
    """
    :return IResource: A resource which can be rendered to produce a **BAD
        REQUEST** response.
    """
    return ErrorPage(
        BAD_REQUEST,
        b"Bad Request",
        reason.encode("utf-8"),
    )
