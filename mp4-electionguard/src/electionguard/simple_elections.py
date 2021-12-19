from typing import Optional, Tuple, List, Dict, Final

from electionguard.chaum_pedersen import (
    make_disjunctive_chaum_pedersen_known_nonce,
    make_constant_chaum_pedersen_proof_known_nonce,
    make_constant_chaum_pedersen_proof_known_secret_key,
)
from electionguard.elgamal import elgamal_encrypt, elgamal_add, ElGamalCiphertext
from electionguard.group import ElementModQ, add_q, rand_range_q, ZERO_MOD_Q
from electionguard.logs import log_error
from electionguard.nonces import Nonces
from electionguard.simple_election_data import (
    CiphertextBallot,
    PlaintextBallot,
    PlaintextSelection,
    CiphertextSelection,
    PrivateElectionContext,
    CiphertextSelectionTally,
    AnyElectionContext,
    PlaintextSelectionWithProof,
    PlaintextBallotWithProofs,
)
from electionguard.utils import list_of_option_to_option_list

PLACEHOLDER_NAME: Final[str] = "PLACEHOLDER"


def encrypt_selection(
    context: AnyElectionContext,
    selection: PlaintextSelection,
    seed_nonce: ElementModQ,
) -> Tuple[CiphertextSelection, ElementModQ]:
    """
    Given a selection and the necessary election context, encrypts the selection and returns the
    encrypted selection plus the encryption nonce. If anything goes wrong, `None` is returned.
    """

    # TODO: implement this for part 1
    # raise RuntimeError("not implemented yet")
    pub_key = context.get_public_key()
    ciphertext = elgamal_encrypt(selection.choice, seed_nonce, pub_key)
    zero_or_one_proof = make_disjunctive_chaum_pedersen_known_nonce(ciphertext, selection.choice, seed_nonce, pub_key, context.hash_header, seed_nonce)
    encryption_selection = CiphertextSelection(selection.name, ciphertext, zero_or_one_proof)

    return encryption_selection, seed_nonce


def encrypt_ballot(
    context: AnyElectionContext,
    ballot: PlaintextBallot,
    seed_nonce: ElementModQ,
    interpret_ballot: bool = True,
) -> Optional[CiphertextBallot]:
    """
    Given a ballot and the necessary election context, encrypts the ballot and returns the
    ciphertext. If anything goes wrong, `None` is returned. If the number of selections is greater
    than allowed for this ballot style, we call that an "overvoted" ballot. There's no valid
    encryption of that, so we normally "interpret" the ballot first, replacing the votes with an
    undervote (i.e., all selections blank). The `interpret_ballot` flag, if false, overrides this
    behavior, allowing for the creation of malformed ballot encryptions.
    """

    # TODO: implement this for part 2, be sure to use your encrypt_selection from part 1.
    # raise RuntimeError("not implemented yet")
    ciphertext = elgamal_encrypt(0, seed_nonce, context.get_public_key())

    if ballot.is_overvoted(context.max_votes_cast) and interpret_ballot:
        votes_cast = sum([s.choice for s in ballot.selections])
        selections = [encrypt_selection(context, PlaintextSelection(ballot.selections[0].name, 0), seed_nonce)[0]] \
                        +[encrypt_selection(context, PlaintextSelection(s.name, 0), Nonces(seed_nonce)[0])[0] for s in ballot.selections[1:]]
        valid_sum_proof = make_constant_chaum_pedersen_proof_known_nonce(ciphertext, votes_cast, seed_nonce, context.get_public_key(), seed_nonce, context.hash_header)
        ciphertext_ballot = CiphertextBallot(ballot.ballot_id, selections, valid_sum_proof)

    else:
        selections = []
        nonce = ZERO_MOD_Q
        for s in ballot.selections:
            selections.append(encrypt_selection(context, s, seed_nonce)[0])
            ciphertext = elgamal_add(ciphertext, elgamal_encrypt(s.choice, seed_nonce, context.get_public_key()))
            nonce = add_q(nonce, seed_nonce)
            seed_nonce = Nonces(seed_nonce)[0]
        votes_cast = sum([s.choice for s in ballot.selections])

        for _ in range(votes_cast, context.max_votes_cast):
            selections.append(encrypt_selection(context, PlaintextSelection(PLACEHOLDER_NAME, 1), seed_nonce)[0])
            ciphertext = elgamal_add(ciphertext, elgamal_encrypt(1, seed_nonce, context.get_public_key()))
            nonce = add_q(nonce, seed_nonce)
            seed_nonce = Nonces(seed_nonce)[0]

        if interpret_ballot:
            plaintext = context.max_votes_cast
        else:
            plaintext = max(votes_cast, context.max_votes_cast)

        valid_sum_proof = make_constant_chaum_pedersen_proof_known_nonce(ciphertext, plaintext, nonce, context.get_public_key(), seed_nonce, context.hash_header)
        ciphertext_ballot = CiphertextBallot(ballot.ballot_id, selections, valid_sum_proof)

    return ciphertext_ballot


def encrypt_ballots(
    context: AnyElectionContext, ballots: List[PlaintextBallot], seed_nonce: ElementModQ
) -> Optional[List[CiphertextBallot]]:
    """
    Given a list of ballots and the necessary election context, encrypts the ballots and returns
    a list of the ciphertexts. If anything goes wrong, `None` is returned. This also ensures that
    the nonce seeds are unique for each ballot.
    """

    # TODO: implement this for part 2. Be sure to use your encrypt_ballot.
    # raise RuntimeError("not implemented yet")
    output = []
    for ballot in ballots:
        output.append(encrypt_ballot(context, ballot, seed_nonce))
        seed_nonce = Nonces(seed_nonce)[ballot.num_selections()]

    return output


def validate_encrypted_selection(
    context: AnyElectionContext, selection: CiphertextSelection
) -> bool:
    """Validates the proof on an encrypted selection. Returns true if everything is good."""

    # TODO: implement this for part 1.
    # raise RuntimeError("not implemented yet")
    if selection.zero_or_one_proof.is_valid(selection.ciphertext, context.get_public_key(), context.hash_header):
        return True
    else:
        return False


def validate_encrypted_ballot(
    context: AnyElectionContext, ballot: CiphertextBallot
) -> bool:
    """Validates all the proofs on the encrypted ballot. Returns true if everything is good."""

    # TODO: implement this for part 2. Be sure to use your validate_encrypted_selection from part 1.
    # raise RuntimeError("not implemented yet")
    is_valid = True
    if context.max_votes_cast >= ballot.valid_sum_proof.constant:
        for selection in ballot.selections:
            if not validate_encrypted_selection(context, selection):
                is_valid = False
                break
    else:
        is_valid = False

    return is_valid


def decrypt_selection(
    context: PrivateElectionContext,
    selection: CiphertextSelection,
    seed: ElementModQ = rand_range_q(1),
) -> Optional[PlaintextSelectionWithProof]:
    """
    Given an encrypted selection and the necessary crypto context, decrypts it, returning
    the plaintext selection along with a Chaum-Pedersen proof of its correspondence to the
    ciphertext. The optional seed is used for computing the proof.
    """

    # TODO: implement this for part 1
    # raise RuntimeError("not implemented yet")
    ciphertext = selection.ciphertext
    plaintext = ciphertext.decrypt(context.keypair)
    selection = PlaintextSelection(selection.name, plaintext)
    decryption_proof = make_constant_chaum_pedersen_proof_known_secret_key(ciphertext, plaintext, context.keypair.secret_key, seed, context.hash_header)

    return PlaintextSelectionWithProof(selection, decryption_proof)


def decrypt_ballot(
    context: PrivateElectionContext,
    ballot: CiphertextBallot,
    seed: ElementModQ = rand_range_q(1),
) -> Optional[PlaintextBallotWithProofs]:
    """
    Given an encrypted ballot and the necessary crypto context, decrypts it. Each
    decryption includes the necessary Chaum-Pedersen decryption proofs as well.
    The optional seed is used for the decryption proofs.
    """

    # TODO: implement this for part 2. Be sure to use your decrypt_selection from part 1.
    # raise RuntimeError("not implemented yet")
    selections = []
    for s in ballot.selections:
        if s.name != PLACEHOLDER_NAME:
            selections.append(decrypt_selection(context, s, seed))
            seed = Nonces(seed)[0]

    return PlaintextBallotWithProofs(ballot.ballot_id, selections)


def validate_decrypted_selection(
    context: AnyElectionContext,
    plaintext: PlaintextSelectionWithProof,
    ciphertext: CiphertextSelection,
) -> bool:
    """
    Validates that the plaintext is provably generated from the ciphertext. Returns true
    if everything is good.
    """

    # TODO: implement this for part 1.
    # raise RuntimeError("not implemented yet")
    if plaintext.decryption_proof.is_valid(ciphertext.ciphertext, context.get_public_key(), context.hash_header, plaintext.selection.choice):
        return True
    else:
        return False


def validate_decrypted_ballot(
    context: AnyElectionContext,
    plaintext: PlaintextBallotWithProofs,
    ciphertext: CiphertextBallot,
) -> bool:
    """Validates that the plaintext is provably generated from the ciphertext. Returns true if everything is good."""

    # TODO: implement this for part 2. Be sure to use your validate_decrypted_selection from part 1.
    # raise RuntimeError("not implemented yet")
    is_valid = True
    for pt, ct in zip(plaintext.selections, ciphertext.selections):
        if not validate_decrypted_selection(context, pt, ct):
            is_valid = False
            break
    return is_valid


def tally_encrypted_ballots(
    context: AnyElectionContext, ballots: List[CiphertextBallot]
) -> List[CiphertextSelectionTally]:
    """Homomorphically accumulates the encrypted ballots, returning list of tallies, one per selection."""

    # TODO: implement this for part 2.
    # raise RuntimeError("not implemented yet")
    dict = {}
    for ballot in ballots:
        for selection in ballot.selections:
            if dict.__contains__(selection.name):
                dict[selection.name] = elgamal_add(dict[selection.name], selection.ciphertext)
            else:
                dict[selection.name] = selection.ciphertext
    output = [CiphertextSelectionTally(key, value) for key, value in zip(dict.keys(), dict.values())]

    return output


def decrypt_tally(
    context: PrivateElectionContext,
    selection: CiphertextSelectionTally,
    seed: ElementModQ = rand_range_q(1),
) -> Optional[PlaintextSelectionWithProof]:
    """Given an encrypted, tallied selection, and the necessary crypto context, decrypts it,
    returning the plaintext selection along with a Chaum-Pedersen proof of its correspondence to the
    ciphertext. The optional seed is used for computing the proof."""

    # TODO: implement this for part 2.
    # raise RuntimeError("not implemented yet")
    ciphertext = selection.total
    plaintext = ciphertext.decrypt(context.keypair)
    selection = PlaintextSelection(selection.name, plaintext)
    decryption_proof = make_constant_chaum_pedersen_proof_known_secret_key(ciphertext, plaintext, context.keypair.secret_key, seed, context.hash_header)

    return PlaintextSelectionWithProof(selection, decryption_proof)


def decrypt_tallies(
    context: PrivateElectionContext,
    tally: List[CiphertextSelectionTally],
    seed: ElementModQ = rand_range_q(1),
) -> Optional[List[PlaintextSelectionWithProof]]:
    """Given a list of encrypted tallies and the necessary crypto context, does the
    decryption on the entire list. The optional seed is used for computing the proofs."""

    # TODO: implement this for part 2. Be sure to use decrypt_tally.
    # raise RuntimeError("not implemented yet")
    output = [decrypt_tally(context, tally[0], seed)] \
                + [decrypt_tally(context, i, Nonces(seed=seed)[0]) for i in tally[1:]]

    return output


def validate_tally(
    context: AnyElectionContext,
    tally_plaintext: PlaintextSelectionWithProof,
    tally_ciphertext: CiphertextSelectionTally,
) -> bool:
    """Validates that the plaintext is provably generated from the ciphertext. Returns true if everything is good."""

    # TODO: implement this for part 2. It's similar to, but not the same as validate_decrypted_ballot.
    # raise RuntimeError("not implemented yet")
    if tally_plaintext.decryption_proof.is_valid(tally_ciphertext.total, context.get_public_key(), context.hash_header):
        return True
    else:
        return False



def validate_tallies(
    context: AnyElectionContext,
    tally_plaintext: List[PlaintextSelectionWithProof],
    tally_ciphertext: List[CiphertextSelectionTally],
) -> bool:
    """Validates that the plaintext is provably generated from the ciphertext for every tally. Returns true if
    everything is good."""

    # TODO: implement this for part 2. Be sure to use validate_tally.
    # raise RuntimeError("not implemented yet")
    is_valid = True
    for pt, ct in zip(tally_plaintext, tally_ciphertext):
        if not validate_tally(context, pt, ct):
            is_valid = False
            break
    
    return is_valid


def tally_plaintext_ballots(
    context: AnyElectionContext, ballots: List[PlaintextBallot]
) -> PlaintextBallot:
    """Given a list of ballots, adds their counters and returns a ballot representing the totals of the contest."""

    # You may find this method to be handy. We use it for some unit tests.

    totals: Dict[str, int] = {}
    for b in ballots:
        for s in b.selections:
            if s.name not in totals:
                totals[s.name] = s.choice
            else:
                totals[s.name] += s.choice

    return PlaintextBallot(
        "TOTALS", [PlaintextSelection(name, totals[name]) for name in context.names]
    )
