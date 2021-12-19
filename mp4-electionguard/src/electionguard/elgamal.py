from typing import Optional, Union, NamedTuple

from .dlog import discrete_log
from .group import (
    ElementModQ,
    ElementModP,
    g_pow_p,
    mult_p,
    pow_p,
    ONE_MOD_P,
    ZERO_MOD_Q,
    rand_range_q,
    div_p,
    int_to_q_unchecked,
    Q,
    make_formula,
)
from .hash import hash_elems
from .logs import log_error
from .utils import get_optional

ElGamalPublicKey = ElementModP
ElGamalSecretKey = ElementModQ


class ElGamalKeyPair(NamedTuple):
    """A tuple of an ElGamal secret key and public key."""

    secret_key: ElGamalSecretKey
    public_key: ElGamalPublicKey


class ElGamalCiphertext(NamedTuple):
    """
    An "exponential ElGamal ciphertext" (i.e., with the plaintext in the exponent to allow for
    homomorphic addition). Create one with `elgamal_encrypt`. Add them with `elgamal_add`.
    Decrypt using one of the supplied instance methods.
    """

    pad: ElementModP
    """pad or alpha"""

    data: ElementModP
    """encrypted data or beta"""

    def decrypt_known_product(self, product: ElementModP) -> Optional[int]:
        """
        Decrypts an ElGamal ciphertext with a "known product" (the blinding factor used in the encryption).

        :param product: The known product (blinding factor).
        :return: A plaintext message.
        """
        return discrete_log(div_p(self.data, product))

    def decrypt(
        self, secret_key: Union[ElGamalSecretKey, ElGamalKeyPair]
    ) -> Optional[int]:
        """
        Decrypt an ElGamal ciphertext using a known ElGamal secret key.

        :param secret_key: The corresponding ElGamal secret key.
        :return: A plaintext message.
        """
        if isinstance(secret_key, ElGamalKeyPair):
            secret_key = secret_key.secret_key

        return self.decrypt_known_product(pow_p(self.pad, secret_key))

    def decrypt_known_nonce(
        self, public_key: Union[ElGamalPublicKey, ElGamalKeyPair], nonce: ElementModQ
    ) -> Optional[int]:
        """
        Decrypt an ElGamal ciphertext using a known nonce and the ElGamal public key.

        :param public_key: The corresponding ElGamal public key.
        :param nonce: The secret nonce used to create the ciphertext.
        :return: A plaintext message.
        """

        if isinstance(public_key, ElGamalKeyPair):
            public_key = public_key.public_key

        return self.decrypt_known_product(pow_p(public_key, nonce))

    def crypto_hash(self) -> ElementModQ:
        """
        Computes a cryptographic hash of this ciphertext.
        """
        return hash_elems(self.pad, self.data)


def elgamal_keypair_from_secret(a: ElGamalSecretKey) -> ElGamalKeyPair:
    """
    Given an ElGamal secret key (typically, a random number in [2,Q)), returns
    an ElGamal keypair, consisting of the given secret key a and public key g^a.
    """
    secret_key_int = a.to_int()
    if secret_key_int < 2:
        log_error("ElGamal secret key needs to be in [2,Q).")
        raise RuntimeError("ElGamal secret key needs to be in [2,Q).")

    return ElGamalKeyPair(a, g_pow_p(a))


def elgamal_keypair_random() -> ElGamalKeyPair:
    """
    Create a random elgamal keypair

    :return: random elgamal key pair
    """
    return get_optional(
        elgamal_keypair_from_secret(
            rand_range_q(2).update_formula(make_formula("random_secret_key"))
        )
    )


def elgamal_encrypt(
    m: int, nonce: ElementModQ, public_key: Union[ElGamalKeyPair, ElGamalPublicKey]
) -> ElGamalCiphertext:
    """
    Encrypts a message with a given random nonce and an ElGamal public key.

    :param m: Message to elgamal_encrypt; must be an integer in [0,Q).
    :param nonce: Randomly chosen nonce in [1,Q).
    :param public_key: ElGamal public key.
    :return: A ciphertext tuple.
    """
    if nonce == ZERO_MOD_Q:
        log_error("ElGamal encryption requires a non-zero nonce")
        raise RuntimeError("ElGamal encryption requires a non-zero nonce")

    if m < 0:
        log_error("Can't encrypt a negative message")
        raise RuntimeError("Can't encrypt a negative message")

    if m >= Q:
        log_error("Can't encrypt a message bigger than Q")
        raise RuntimeError("Can't encrypt a message bigger than Q")

    pk = public_key.public_key if isinstance(public_key, ElGamalKeyPair) else public_key
    return ElGamalCiphertext(
        g_pow_p(nonce), mult_p(g_pow_p(int_to_q_unchecked(m)), pow_p(pk, nonce))
    )


def elgamal_add(*ciphertexts: ElGamalCiphertext) -> ElGamalCiphertext:
    """
    Homomorphically accumulates one or more ElGamal ciphertexts by pairwise multiplication. The exponents
    of vote counters will add.
    """
    assert len(ciphertexts) != 0, "Must have one or more ciphertexts for elgamal_add"

    pads = [c.pad for c in ciphertexts]
    data = [c.data for c in ciphertexts]
    return ElGamalCiphertext(mult_p(*pads), mult_p(*data))


def elgamal_combine_public_keys(
    *keys: Union[ElGamalPublicKey, ElGamalKeyPair]
) -> ElGamalPublicKey:
    """
    Combines multiple ElGamal public keys into a single public key. The corresponding secret keys can
    do "partial decryption" operations that can be later combined. See, e.g.,
    [ElGamalCiphertext.partialDecryption] and [combinePartialDecryptions].
    """
    # TODO: implement this for part 1. Don't forget to use 'isinstance' to make
    #   sure this works for both ElGamalPublicKey or ElGamalKeyPair.
    # raise RuntimeError("not implemented yet")
    single_pub_key = ONE_MOD_P
    for key in keys:
        key = key.public_key if isinstance(key, ElGamalKeyPair) else key
        single_pub_key = mult_p(single_pub_key, key)
    return single_pub_key


ElGamalPartialDecryption = ElementModP


def elgamal_partial_decryption(
    key: Union[ElGamalSecretKey, ElGamalKeyPair], ciphertext: ElGamalCiphertext
) -> ElGamalPartialDecryption:
    """
    Computes a partial decryption of the ciphertext with a secret key or keypair. See
    [ElGamalCiphertext.combinePartialDecryptions] for extracting the plaintext.
    """
    # TODO: implement this for part 1. Don't forget to use 'isinstance' to make
    #   sure this works for both ElGamalSecretKey or ElGamalKeyPair.
    # raise RuntimeError("not implemented yet")
    if isinstance(key, ElGamalKeyPair):
        return pow_p(ciphertext.pad, key.secret_key)
    else:
        return pow_p(ciphertext.pad, key)


def elgamal_combine_partial_decryptions(
    ciphertext: ElGamalCiphertext, *partial_decryptions: ElGamalPartialDecryption
) -> Optional[int]:
    """
    Given a series of partial decryptions of the ciphertext, combines them together to complete the
    decryption process.
    """
    # TODO: implement this for part 1.
    # raise RuntimeError("not implemented yet")
    product = ONE_MOD_P
    for decryption_share in partial_decryptions:
        product = mult_p(product, decryption_share)
    
    return ciphertext.decrypt_known_product(product)