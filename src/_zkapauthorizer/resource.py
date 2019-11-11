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

from json import (
    loads, dumps,
)

from twisted.logger import (
    Logger,
)
from twisted.web.http import (
    BAD_REQUEST,
)
from twisted.web.resource import (
    ErrorPage,
    NoResource,
    Resource,
)

from ._base64 import (
    urlsafe_b64decode,
)

from .controller import (
    PaymentController,
    NonRedeemer,
)

def from_configuration(node_config, store, redeemer=None):
    """
    Instantiate the plugin root resource using data from its configuration
    section in the Tahoe-LAFS configuration file::

        [storageclient.plugins.privatestorageio-zkapauthz-v1]
        # nothing yet

    :param _Config node_config: An object representing the overall node
        configuration.  The plugin configuration can be extracted from this.
        This is also used to read and write files in the private storage area
        of the node's persistent state location.

    :param VoucherStore store: The store to use.

    :param IRedeemer redeemer: The voucher redeemer to use.  If ``None`` a
        sensible one is constructed.

    :return IResource: The root of the resource hierarchy presented by the
        client side of the plugin.
    """
    if redeemer is None:
        redeemer = NonRedeemer()
    controller = PaymentController(store, redeemer)
    root = Resource()
    root.putChild(
        b"voucher",
        _VoucherCollection(
            store,
            controller,
        ),
    )
    root.putChild(
        b"zkap",
        _ZKAPCollection(
            store,
            controller,
        ),
    )
    return root


def application_json(request):
    """
    Set the given request's response content-type to ``application/json``.

    :param twisted.web.iweb.IRequest request: The request to modify.
    """
    request.responseHeaders.setRawHeaders(u"content-type", [u"application/json"])


class _ZKAPCollection(Resource):
    """
    This class implements inspection of ZKAPs.  Users **GET** this resource to
    find out about ZKAPs in the system.
    """
    _log = Logger()

    def __init__(self, store, controller):
        self._store = store
        self._controller = controller
        Resource.__init__(self)

    def render_GET(self, request):
        """
        Retrieve some ZKAPs and associated informatin.
        """
        application_json(request)
        return dumps({u"total": 0, u"zkaps": []})



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
            return bad_request(u"request object must have exactly one key: 'voucher'").render(request)
        voucher = payload[u"voucher"]
        if not is_syntactic_voucher(voucher):
            return bad_request(u"submitted voucher is syntactically invalid").render(request)

        self._log.info("Accepting a voucher ({voucher}) for redemption.", voucher=voucher)
        self._controller.redeem(voucher)
        return b""


    def render_GET(self, request):
        application_json(request)
        return dumps({
            u"vouchers": list(
                voucher.marshal()
                for voucher
                in self._store.list()
            ),
        })


    def getChild(self, segment, request):
        voucher = segment.decode("utf-8")
        if not is_syntactic_voucher(voucher):
            return bad_request()
        try:
            voucher = self._store.get(voucher)
        except KeyError:
            return NoResource()
        return VoucherView(voucher)


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
        BAD_REQUEST, b"Bad Request", reason.encode("utf-8"),
    )
