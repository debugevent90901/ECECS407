# support for computing discrete logs, with a cache so they're never recomputed

import asyncio
from typing import Dict, Optional

from .group import G, ElementModP, ONE_MOD_P, mult_p, int_to_p_unchecked
from .logs import log_error

__dlog_cache: Dict[ElementModP, int] = {ONE_MOD_P: 0}
__dlog_max_element = ONE_MOD_P
__dlog_max_exponent = 0
__DLOG_MAX = 100_000_000

__dlog_lock = asyncio.Lock()


def discrete_log(e: ElementModP) -> Optional[int]:
    """
    Computes the discrete log (base g, mod p) of the given element,
    with internal caching of results. Should run efficiently when called
    multiple times when the exponent is at most in the single-digit millions.
    Performance will degrade if it's much larger.

    If the exponent is enormous (greater than a hundred million or so), then
    this function will give up and return `None`, which the caller should
    check.

    Note: *this function is thread-safe*. For the best possible performance,
    pre-compute the discrete log of a number you expect to have the biggest
    exponent you'll ever see. After that, the cache will be fully loaded,
    and every call will be nothing more than a dictionary lookup.
    """
    global __dlog_cache

    # no need for mutually exclusive access when reading from the cache
    if e in __dlog_cache:
        return __dlog_cache[e]
    else:
        return asyncio.run(__discrete_log_internal(e))


async def __discrete_log_internal(e: ElementModP) -> Optional[int]:
    global __dlog_cache
    global __dlog_max_element
    global __dlog_max_exponent
    global __dlog_lock

    async with __dlog_lock:
        # We need to check the dict again; it might have changed.
        if e in __dlog_cache:
            return __dlog_cache[e]

        g = int_to_p_unchecked(G)
        while e != __dlog_max_element:
            __dlog_max_exponent = __dlog_max_exponent + 1
            if __dlog_max_exponent >= __DLOG_MAX:
                log_error(f"Discrete log failure: exponent was > {__DLOG_MAX}")
                return None
            __dlog_max_element = mult_p(g, __dlog_max_element)
            __dlog_cache[__dlog_max_element] = __dlog_max_exponent

        return __dlog_cache[__dlog_max_element]


# Under typical Python circumstances, all of this fancy mutual exclusion logic is completely
# unnecessary, because Python has a global lock, so only one thread is really running at
# a time.
# https://medium.com/python-features/pythons-gil-a-hurdle-to-multithreaded-program-d04ad9c1a63

# Of course, there are other implementations of Python besides the usual CPython, so this
# code might be necessary in such circumstances, and it doesn't hurt anything to be here now.
