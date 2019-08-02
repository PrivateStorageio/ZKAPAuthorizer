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
payment codes for fresh tokens.

In the future it should also allow users to read statistics about token usage.
"""

from json import (
    loads, dumps,
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

from .model import (
    PaymentReferenceStore,
)
from .controller import (
    PaymentController,
)

def from_configuration(node_config, store=None):
    """
    Instantiate the plugin root resource using data from its configuration
    section in the Tahoe-LAFS configuration file::

        [storageclient.plugins.privatestorageio-satauthz-v1]
        # nothing yet

    :param _Config node_config: An object representing the overall node
        configuration.  The plugin configuration can be extracted from this.
        This is also used to read and write files in the private storage area
        of the node's persistent state location.

    :param PaymentReferenceStore store: The store to use.  If ``None`` a
        sensible one is constructed.

    :return IResource: The root of the resource hierarchy presented by the
        client side of the plugin.
    """
    if store is None:
        store = PaymentReferenceStore.from_node_config(node_config)
    controller = PaymentController(store)
    root = Resource()
    root.putChild(
        b"payment-reference-number",
        _PaymentReferenceNumberCollection(
            store,
            controller,
        ),
    )
    return root


class _PaymentReferenceNumberCollection(Resource):
    """
    This class implements redemption of payment reference numbers (PRNs).
    Users **PUT** such numbers to this resource which delegates redemption
    responsibilities to the redemption controller.  Child resources of this
    resource can also be retrieved to monitor the status of previously
    submitted PRNs.
    """
    def __init__(self, store, controller):
        self._store = store
        self._controller = controller
        Resource.__init__(self)


    def render_PUT(self, request):
        try:
            payload = loads(request.content.read())
        except Exception:
            return bad_request().render(request)
        if payload.keys() != [u"payment-reference-number"]:
            return bad_request().render(request)
        prn = payload[u"payment-reference-number"]
        if not isinstance(prn, unicode):
            return bad_request().render(request)
        if not prn.strip():
            return bad_request().render(request)
        try:
            urlsafe_b64decode(prn.encode("ascii"))
        except Exception:
            return bad_request().render(request)

        self._controller.redeem(prn)
        return b""


    def render_GET(self, request):
        request.responseHeaders.setRawHeaders(u"content-type", [u"application/json"])
        return dumps({
            u"payment-reference-numbers": list(
                prn.marshal()
                for prn
                in self._store.list()
            ),
        })


    def getChild(self, segment, request):
        prn = segment
        try:
            urlsafe_b64decode(prn)
        except Exception:
            return bad_request()
        try:
            payment_reference = self._store.get(prn)
        except KeyError:
            return NoResource()
        return PaymentReferenceView(payment_reference)



class PaymentReferenceView(Resource):
    def __init__(self, reference):
        self._reference = reference
        Resource.__init__(self)


    def render_GET(self, request):
        request.responseHeaders.setRawHeaders(u"content-type", [u"application/json"])
        return self._reference.to_json()


def bad_request():
    return ErrorPage(
        BAD_REQUEST, b"Bad Request", b"Bad Request",
    )
