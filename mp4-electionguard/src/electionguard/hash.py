from abc import abstractmethod
from hashlib import sha256
from typing import (
    Union,
    Protocol,
    runtime_checkable,
    Sequence,
    List,
    Iterable,
)

from .group import (
    ElementModPOrQ,
    ElementModQ,
    Q_MINUS_ONE,
    int_to_q_unchecked,
    ElementModP,
    make_formula,
)


@runtime_checkable
class CryptoHashable(Protocol):
    """
    Denotes hashable
    """

    @abstractmethod
    def crypto_hash(self) -> ElementModQ:
        """
        Generates a hash given the fields on the implementing instance.
        """
        ...


@runtime_checkable
class CryptoHashCheckable(Protocol):
    """
    Checkable version of crypto hash
    """

    @abstractmethod
    def crypto_hash_with(self, seed_hash: ElementModQ) -> ElementModQ:
        """
        Generates a hash with a given seed that can be checked later against the seed and class metadata.
        """
        ...


# All the "atomic" types that we know how to hash.
CRYPTO_HASHABLE_T = Union[CryptoHashable, ElementModPOrQ, str, int, None]

# "Compound" types that we know how to hash. Note that we're using Sequence, rather than List,
# because Sequences are read-only, and thus safely covariant. All this really means is that
# we promise never to mutate any list that you pass to hash_elems.
CRYPTO_HASHABLE_ALL = Union[
    Sequence[CRYPTO_HASHABLE_T],
    CRYPTO_HASHABLE_T,
]


def hash_elems(*a: CRYPTO_HASHABLE_ALL) -> ElementModQ:
    """
    Given zero or more elements, calculate their cryptographic hash
    using SHA256. Allowed element types are `ElementModP`, `ElementModQ`,
    `str`, or `int`, anything implementing `CryptoHashable`, and lists
    or optionals of any of those types.

    :param a: Zero or more elements of any of the accepted types.
    :return: A cryptographic hash of these elements, concatenated.
    """
    h = sha256()
    h.update("|".encode("utf-8"))
    formula_me = []
    for x in a:
        # We could just use str(x) for everything, but then we'd have a resulting string
        # that's a bit Python-specific, and we'd rather make it easier for other languages
        # to exactly match this hash function.

        if isinstance(x, (ElementModP, ElementModQ)):
            hash_me = x.to_hex()
            formula_me.append(x.formula)
        elif isinstance(x, CryptoHashable):
            hash_me = x.crypto_hash().to_hex()
            formula_me.append(str(x))
        elif isinstance(x, str):
            # strings are iterable, so it's important to handle them before the following check
            hash_me = x
            formula_me.append(x)
        elif isinstance(x, int):
            hash_me = str(x)
            formula_me.append(str(x))
        elif isinstance(x, (Sequence, List, Iterable)):
            # The simplest way to deal with lists, tuples, and such are to crunch them recursively.
            # But we special-case the empty list, because it hashes to "null" yet has a formula
            # of []. Note that empty lists and None will never occur in practice, anywhere in
            # ElectionGuard, but hash_elems needs to handle them correctly, just in case.
            if not x:
                hash_me = "null"
                formula_me.append([])
            else:
                tmp = hash_elems(*x)
                hash_me = tmp.to_hex()
                formula_me.append(tmp.formula)
        elif not x:
            hash_me = "null"
            formula_me.append("null")
        else:
            hash_me = str(x)
            formula_me.append(str(x))

        h.update((hash_me + "|").encode("utf-8"))

    # We don't need the checked version of int_to_q, because the
    # modulo operation here guarantees that we're in bounds.
    return int_to_q_unchecked(
        int.from_bytes(h.digest(), byteorder="big") % Q_MINUS_ONE,
        formula=make_formula("hash", *formula_me),
    )
