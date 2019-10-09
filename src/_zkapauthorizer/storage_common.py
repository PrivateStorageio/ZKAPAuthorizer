
from base64 import (
    b64encode,
)

from math import (
    ceil,
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

# The number of bytes we're willing to store for a lease period for each pass
# submitted.
BYTES_PER_PASS = 128 * 1024

def required_passes(bytes_per_pass, share_nums, share_size):
    """
    Calculate the number of passes that are required to store ``stored_bytes``
    for one lease period.

    :param int stored_bytes: A number of bytes of storage for which to
        calculate a price in passes.

    :return int: The number of passes.
    """
    return int(
        ceil(
            (len(share_nums) * share_size) / bytes_per_pass,
        ),
    )
