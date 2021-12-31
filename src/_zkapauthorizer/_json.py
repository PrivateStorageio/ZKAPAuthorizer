from __future__ import absolute_import, division, print_function, unicode_literals

from future.utils import PY2

if PY2:
    from future.builtins import (  # noqa: F401
        filter,
        map,
        zip,
        ascii,
        chr,
        hex,
        input,
        next,
        oct,
        open,
        pow,
        round,
        super,
        bytes,
        dict,
        list,
        object,
        range,
        str,
        max,
        min,
    )

from six import ensure_binary
from json import dumps as _dumps

def dumps(o):
    return ensure_binary(_dumps(o))
