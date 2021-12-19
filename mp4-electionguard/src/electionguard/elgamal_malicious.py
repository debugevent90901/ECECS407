from typing import Union, Tuple

from electionguard.chaum_pedersen import GenericChaumPedersenProof, make_chaum_pedersen_generic
from electionguard.elgamal import (
    ElGamalSecretKey,
    ElGamalKeyPair,
    ElGamalCiphertext,
    ElGamalPartialDecryption,
    elgamal_partial_decryption
)
from electionguard.group import (
    ElementModQ,
    pow_p,
    g_pow_p,
    a_plus_bc_q,
    mult_p,
    mult_inv_p,
    int_to_q,
    _Q_gmp,
    G_MOD_P
)


def elgamal_partial_decryption_with_proof(
    key: Union[ElGamalSecretKey, ElGamalKeyPair],
    ciphertext: ElGamalCiphertext,
    seed_nonce: ElementModQ,
) -> Tuple[ElGamalPartialDecryption, GenericChaumPedersenProof]:
    """
    Computes a partial decryption of the ciphertext with a secret key or keypair along with
    a Chaum-Pedersen proof of its correspondence to the ciphertext.
    """
    # TODO: implement this for part 3.
    # raise RuntimeError("not implemented yet")
    if not isinstance(key, ElGamalSecretKey):
        key = key.secret_key
    partial_decryption = elgamal_partial_decryption(key, ciphertext)
    cham_pedersen_proof = make_chaum_pedersen_generic(G_MOD_P, ciphertext.pad, key, seed_nonce)
    
    return partial_decryption, cham_pedersen_proof


def elgamal_partial_decryption_with_fake_proof(
    key: Union[ElGamalSecretKey, ElGamalKeyPair],
    ciphertext: ElGamalCiphertext,
    seed_nonce: ElementModQ,
) -> Tuple[ElGamalPartialDecryption, GenericChaumPedersenProof]:
    """
    Computes a partial decryption of the ciphertext with a secret key or keypair along with
    a fake Chaum-Pedersen proof that could pass the validation process but is not consistent
    with the ciphertext.
    """
    # TODO: implement this for part 3.
    raise RuntimeError("not implemented yet")
