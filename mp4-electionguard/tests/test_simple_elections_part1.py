import unittest
from typing import Tuple, List

from grade.decorators import weight
from grade.mixins import ScoringMixin
from hypothesis import HealthCheck, Phase
from hypothesis import given, settings
from hypothesis.strategies import integers

from electionguard.elgamal import (
    ElGamalKeyPair,
    elgamal_combine_public_keys,
    elgamal_encrypt,
    elgamal_partial_decryption,
    elgamal_combine_partial_decryptions,
)
from electionguard.elgamal_malicious import (
    elgamal_partial_decryption_with_fake_proof,
    elgamal_partial_decryption_with_proof,
)
from electionguard.group import (
    ElementModQ,
    int_to_q,
    G_MOD_P,
)
from electionguard.nonces import Nonces
from electionguard.simple_election_data import (
    PrivateElectionContext,
    PlaintextBallot,
    PlaintextSelection,
    PlaintextSelectionWithProof,
)
from electionguard.simple_elections import (
    encrypt_selection,
    decrypt_selection,
    validate_encrypted_selection,
    validate_decrypted_selection,
    CiphertextSelection,
)
from electionguardtest.elgamal import elgamal_keypairs
from electionguardtest.group import elements_mod_q_no_zero
from electionguardtest.simple_elections import (
    context_and_ballots,
)


class TestPart1(unittest.TestCase, ScoringMixin):
    # The 'grade' package that we're using lets us specify weights
    # on unit tests. Unfortunately, if we put the weight annotation
    # on a Hypothesis test method, they don't work together. The
    # workaround is to note that the unit test runner only runs
    # methods that start with "test_" so we put the weights on those,
    # and then Hypothesis works just fine when you annotate any method,
    # regardless of its name, so we just prefix those with "xtest_"
    # and now we can combine 'grade' and 'hypothesis'.
    @weight(2)
    def test_encryption_decryption_inverses(self):
        self.xtest_encryption_decryption_inverses()

    @settings(
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
        max_examples=10,
        # disabling the "shrink" phase, because it runs very slowly
        phases=[Phase.explicit, Phase.reuse, Phase.generate, Phase.target],
    )
    @given(
        context_and_ballots(1),
        elements_mod_q_no_zero("seed"),
    )
    def xtest_encryption_decryption_inverses(
        self,
        context_and_ballots: Tuple[PrivateElectionContext, List[PlaintextBallot]],
        seed_nonce: ElementModQ,
    ):
        context, ballots = context_and_ballots

        selections: List[PlaintextSelection] = ballots[0].selections
        nonces = Nonces(seed_nonce, "part1-ballot-nonces")[0 : len(selections)]
        decrypt_nonces = Nonces(seed_nonce, "part1-ballot-decrypt-nonces")[
            0 : len(selections)
        ]

        encryptions = [
            encrypt_selection(context, selections[i], nonces[i])
            for i in range(0, len(selections))
        ]
        self.assertNotIn(None, encryptions)

        decryptions_with_nonce: List[int] = [
            e[0].ciphertext.decrypt_known_nonce(context.keypair.public_key, e[1])
            for e in encryptions
        ]
        decryptions_with_key: List[PlaintextSelectionWithProof] = [
            decrypt_selection(context, encryptions[i][0], decrypt_nonces[i])
            for i in range(0, len(selections))
        ]

        for s, dn, dk in zip(selections, decryptions_with_nonce, decryptions_with_key):
            self.assertEqual(s.choice, dn)
            self.assertEqual(s, dk.selection)

    @weight(1)
    def test_partial_decryption(self):
        self.xtest_partial_decryption()

    @given(
        elgamal_keypairs("kp1"),
        elgamal_keypairs("kp2"),
        elgamal_keypairs("kp3"),
        integers(0, 1000),
        elements_mod_q_no_zero("nonce"),
    )
    def xtest_partial_decryption(
        self,
        kp1: ElGamalKeyPair,
        kp2: ElGamalKeyPair,
        kp3: ElGamalKeyPair,
        plaintext: int,
        nonce: ElementModQ,
    ):
        combined_key = elgamal_combine_public_keys(kp1, kp2.public_key, kp3)
        ciphertext = elgamal_encrypt(plaintext, nonce, combined_key)
        pd1 = elgamal_partial_decryption(kp1, ciphertext)
        pd2 = elgamal_partial_decryption(kp2.secret_key, ciphertext)
        pd3 = elgamal_partial_decryption(kp3, ciphertext)
        decryption = elgamal_combine_partial_decryptions(ciphertext, pd1, pd2, pd3)

        self.assertEqual(plaintext, decryption)

    @weight(3)
    def test_proof_validation(self):
        self.xtest_proof_validation()

    @settings(
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
        max_examples=10,
        # disabling the "shrink" phase, because it runs very slowly
        phases=[Phase.explicit, Phase.reuse, Phase.generate, Phase.target],
    )
    @given(
        context_and_ballots(1),
        elements_mod_q_no_zero("seed"),
    )
    def xtest_proof_validation(
        self,
        context_and_ballots: Tuple[PrivateElectionContext, List[PlaintextBallot]],
        seed_nonce: ElementModQ,
    ):
        context, ballots = context_and_ballots

        selections: List[PlaintextSelection] = ballots[0].selections
        nonces = Nonces(seed_nonce, "part1-ballot-nonces")[0 : len(selections)]
        decrypt_nonces = Nonces(seed_nonce, "part1-ballot-decrypt-nonces")[
            0 : len(selections)
        ]

        encryptions = [
            encrypt_selection(context, selections[i], nonces[i])
            for i in range(0, len(selections))
        ]
        self.assertNotIn(None, encryptions)

        for e in encryptions:
            self.assertTrue(validate_encrypted_selection(context, e[0]))

        decryptions_with_key: List[PlaintextSelectionWithProof] = [
            decrypt_selection(context, encryptions[i][0], decrypt_nonces[i])
            for i in range(0, len(selections))
        ]

        for d, e in zip(decryptions_with_key, encryptions):
            self.assertTrue(validate_decrypted_selection(context, d, e[0]))

    @weight(3)
    def test_invalid_encryption_proofs_fail(self):
        self.xtest_invalid_encryption_proofs_fail()

    @settings(
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
        max_examples=10,
        # disabling the "shrink" phase, because it runs very slowly
        phases=[Phase.explicit, Phase.reuse, Phase.generate, Phase.target],
    )
    @given(
        context_and_ballots(1),
        elements_mod_q_no_zero("seed"),
    )
    def xtest_invalid_encryption_proofs_fail(
        self,
        context_and_ballots: Tuple[PrivateElectionContext, List[PlaintextBallot]],
        seed_nonce: ElementModQ,
    ):
        context, ballots = context_and_ballots

        selections: List[PlaintextSelection] = ballots[0].selections
        nonces = Nonces(seed_nonce, "part1-ballot-nonces")[0 : len(selections)]
        decryption_nonces = Nonces(seed_nonce, "part1-ballot-decryption-nonces")[
            0 : len(selections)
        ]

        alt_encryption0 = encrypt_selection(
            context, PlaintextSelection("Mallory", 0), int_to_q(3)
        )
        alt_encryption1 = encrypt_selection(
            context, PlaintextSelection("Mallory", 1), int_to_q(3)
        )
        self.assertIsNotNone(alt_encryption0)

        encryptions = [
            encrypt_selection(context, selections[i], nonces[i])
            for i in range(0, len(selections))
        ]
        self.assertNotIn(None, encryptions)

        for e in encryptions:
            bad_e0 = CiphertextSelection(
                e[0].name, alt_encryption0[0].ciphertext, e[0].zero_or_one_proof
            )
            bad_e1 = CiphertextSelection(
                e[0].name, alt_encryption1[0].ciphertext, e[0].zero_or_one_proof
            )
            self.assertFalse(validate_encrypted_selection(context, bad_e0))
            self.assertFalse(validate_encrypted_selection(context, bad_e1))

        decryptions = [
            decrypt_selection(context, encryptions[i][0], decryption_nonces[i])
            for i in range(0, len(selections))
        ]

        for d, e in zip(decryptions, encryptions):
            bad_decryption = PlaintextSelectionWithProof(
                PlaintextSelection(d.selection.name, 0 if d.selection.choice else 1),
                d.decryption_proof,
            )
            self.assertFalse(
                validate_decrypted_selection(context, bad_decryption, e[0])
            )

    @weight(8)
    def test_partial_decryption_DoS(self):
        self.xtest_partial_decryption_DoS()

    @given(
        elgamal_keypairs("kp1"),
        elgamal_keypairs("kp2"),
        elgamal_keypairs("kp3"),
        integers(0, 1000),
        elements_mod_q_no_zero("seed"),
    )
    def xtest_partial_decryption_DoS(
        self,
        kp1: ElGamalKeyPair,
        kp2: ElGamalKeyPair,
        kp3: ElGamalKeyPair,
        plaintext: int,
        seed_nonce: ElementModQ,
    ):
        encrypt_seed, proof_seed, fake_proof_seed = Nonces(
            seed_nonce, "test_partial_decryption_DoS"
        )[:3]
        combined_key = elgamal_combine_public_keys(kp1, kp2.public_key, kp3)
        ciphertext = elgamal_encrypt(plaintext, encrypt_seed, combined_key)

        # 2 points for the honest proof
        pd1, pf = elgamal_partial_decryption_with_proof(kp1, ciphertext, proof_seed)
        self.assertTrue(
            pf.is_valid(g=G_MOD_P, gx=kp1.public_key, h=ciphertext.pad, hx=pd1)
        )
        pd2 = elgamal_partial_decryption(kp2.secret_key, ciphertext)
        pd3 = elgamal_partial_decryption(kp3, ciphertext)
        decryption = elgamal_combine_partial_decryptions(ciphertext, pd1, pd2, pd3)

        self.assertEqual(plaintext, decryption)

        # 6 points for the fake proof
        pd1, pf = elgamal_partial_decryption_with_fake_proof(
            kp1, ciphertext, fake_proof_seed
        )
        self.assertTrue(
            pf.is_valid(g=G_MOD_P, gx=kp1.public_key, h=ciphertext.pad, hx=pd1)
        )
        # TODO: uncomment the line below for testing part 3. The decryption function will run "forever".
        # decryption = elgamal_combine_partial_decryptions(ciphertext, pd1, pd2, pd3)
