
from base64 import (
    b64encode,
)

def _message_maker(label):
    def make_message(storage_index):
        return u"{label} {storage_index}".format(
            label=label,
            storage_index=b64encode(storage_index),
        )
    return make_message

allocate_buckets_message = _message_maker(u"allocate_buckets")
add_lease_message = _message_maker(u"add_lease")
renew_lease_message = _message_maker(u"renew_lease")
slot_testv_and_readv_and_writev_message = _message_maker(u"slot_testv_and_readv_and_writev")
