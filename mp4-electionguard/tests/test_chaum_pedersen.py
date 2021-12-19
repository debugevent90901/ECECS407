import sys
from datetime import timedelta
from typing import Optional
from unittest import TestCase

from hypothesis import given, settings, HealthCheck
from hypothesis.strategies import integers

from electionguard.chaum_pedersen import (
    make_constant_chaum_pedersen_proof_known_nonce,
    make_disjunctive_chaum_pedersen_known_nonce,
    make_chaum_pedersen_generic,
    make_fake_chaum_pedersen_generic,
    make_constant_chaum_pedersen_proof_known_secret_key,
)
from electionguard.elgamal import (
    ElGamalKeyPair,
    elgamal_encrypt,
    elgamal_keypair_from_secret,
)
from electionguard.group import (
    ElementModQ,
    ZERO_MOD_Q,
    TWO_MOD_Q,
    ONE_MOD_Q,
    pow_p,
    int_to_q,
    add_q,
    g_pow_p,
)
from electionguardtest.elgamal import elgamal_keypairs
from electionguardtest.group import (
    elements_mod_q_no_zero,
    elements_mod_q,
)


class TestDisjunctiveChaumPedersen(TestCase):
    def test_djcp_proofs_simple(self):
        # doesn't get any simpler than this
        keypair = elgamal_keypair_from_secret(TWO_MOD_Q)
        nonce = ONE_MOD_Q
        seed = TWO_MOD_Q
        message0 = elgamal_encrypt(0, nonce, keypair.public_key)
        proof0 = make_disjunctive_chaum_pedersen_known_nonce(
            message0, 0, nonce, keypair.public_key, ONE_MOD_Q, seed
        )
        proof0bad = make_disjunctive_chaum_pedersen_known_nonce(
            message0, 1, nonce, keypair.public_key, ONE_MOD_Q, seed
        )
        self.assertTrue(proof0.is_valid(message0, keypair.public_key, ONE_MOD_Q))
        self.assertFalse(proof0bad.is_valid(message0, keypair.public_key, ONE_MOD_Q))

        message1 = elgamal_encrypt(1, nonce, keypair.public_key)
        proof1 = make_disjunctive_chaum_pedersen_known_nonce(
            message1, 1, nonce, keypair.public_key, ONE_MOD_Q, seed
        )
        proof1bad = make_disjunctive_chaum_pedersen_known_nonce(
            message1, 0, nonce, keypair.public_key, ONE_MOD_Q, seed
        )
        self.assertTrue(proof1.is_valid(message1, keypair.public_key, ONE_MOD_Q))
        self.assertFalse(proof1bad.is_valid(message1, keypair.public_key, ONE_MOD_Q))

    def test_djcp_proof_invalid_inputs(self):
        # this is here to push up our coverage
        keypair = elgamal_keypair_from_secret(TWO_MOD_Q)
        nonce = ONE_MOD_Q
        seed = TWO_MOD_Q
        message0 = elgamal_encrypt(0, nonce, keypair.public_key)
        self.assertRaises(
            Exception,
            make_disjunctive_chaum_pedersen_known_nonce,
            message0,
            nonce,
            keypair.public_key,
            seed,
            3,
        )

    @settings(
        deadline=timedelta(milliseconds=2000),
        suppress_health_check=[HealthCheck.too_slow],
        max_examples=10,
    )
    @given(
        elgamal_keypairs("keypair"),
        elements_mod_q_no_zero("nonce"),
        elements_mod_q("seed"),
    )
    def test_djcp_proof_zero(
        self, keypair: ElGamalKeyPair, nonce: ElementModQ, seed: ElementModQ
    ):
        message = elgamal_encrypt(0, nonce, keypair.public_key)
        proof = make_disjunctive_chaum_pedersen_known_nonce(
            message, 0, nonce, keypair.public_key, ONE_MOD_Q, seed
        )
        proof_bad = make_disjunctive_chaum_pedersen_known_nonce(
            message, 1, nonce, keypair.public_key, ONE_MOD_Q, seed
        )
        self.assertTrue(proof.is_valid(message, keypair.public_key, ONE_MOD_Q))
        self.assertFalse(proof_bad.is_valid(message, keypair.public_key, ONE_MOD_Q))

    @settings(
        deadline=timedelta(milliseconds=2000),
        suppress_health_check=[HealthCheck.too_slow],
        max_examples=10,
    )
    @given(
        elgamal_keypairs("keypair"),
        elements_mod_q_no_zero("nonce"),
        elements_mod_q("seed"),
    )
    def test_djcp_proof_one(
        self, keypair: ElGamalKeyPair, nonce: ElementModQ, seed: ElementModQ
    ):
        message = elgamal_encrypt(1, nonce, keypair.public_key)
        proof = make_disjunctive_chaum_pedersen_known_nonce(
            message, 1, nonce, keypair.public_key, ONE_MOD_Q, seed
        )
        proof_bad = make_disjunctive_chaum_pedersen_known_nonce(
            message, 0, nonce, keypair.public_key, ONE_MOD_Q, seed
        )
        self.assertTrue(proof.is_valid(message, keypair.public_key, ONE_MOD_Q))
        self.assertFalse(proof_bad.is_valid(message, keypair.public_key, ONE_MOD_Q))

    @settings(
        deadline=timedelta(milliseconds=2000),
        suppress_health_check=[HealthCheck.too_slow],
        max_examples=10,
    )
    @given(
        elgamal_keypairs("keypair"),
        elements_mod_q_no_zero("nonce"),
        elements_mod_q("seed"),
    )
    def test_djcp_proof_broken(
        self, keypair: ElGamalKeyPair, nonce: ElementModQ, seed: ElementModQ
    ):
        # verify two different ways to generate an invalid C-P proof.
        message = elgamal_encrypt(0, nonce, keypair.public_key)
        message_bad = elgamal_encrypt(2, nonce, keypair.public_key)
        proof = make_disjunctive_chaum_pedersen_known_nonce(
            message, 0, nonce, keypair.public_key, ONE_MOD_Q, seed
        )
        proof_bad = make_disjunctive_chaum_pedersen_known_nonce(
            message_bad, 0, nonce, keypair.public_key, ONE_MOD_Q, seed
        )

        self.assertFalse(proof_bad.is_valid(message_bad, keypair.public_key, ONE_MOD_Q))
        self.assertFalse(proof.is_valid(message_bad, keypair.public_key, ONE_MOD_Q))


class TestConstantChaumPedersen(TestCase):
    def test_ccp_proofs_simple_encryption_of_zero(self):
        keypair = elgamal_keypair_from_secret(TWO_MOD_Q)
        nonce = ONE_MOD_Q
        seed = TWO_MOD_Q
        message = elgamal_encrypt(0, nonce, keypair.public_key)
        proof = make_constant_chaum_pedersen_proof_known_nonce(
            message, 0, nonce, keypair.public_key, seed, ONE_MOD_Q
        )
        bad_proof = make_constant_chaum_pedersen_proof_known_nonce(
            message, 1, nonce, keypair.public_key, seed, ONE_MOD_Q
        )
        self.assertTrue(proof.is_valid(message, keypair.public_key, ONE_MOD_Q))
        self.assertFalse(bad_proof.is_valid(message, keypair.public_key, ONE_MOD_Q))

    def test_ccp_proofs_simple_encryption_of_one(self):
        keypair = elgamal_keypair_from_secret(TWO_MOD_Q)
        nonce = ONE_MOD_Q
        seed = TWO_MOD_Q
        message = elgamal_encrypt(1, nonce, keypair.public_key)
        proof = make_constant_chaum_pedersen_proof_known_nonce(
            message, 1, nonce, keypair.public_key, seed, ONE_MOD_Q
        )
        bad_proof = make_constant_chaum_pedersen_proof_known_nonce(
            message, 0, nonce, keypair.public_key, seed, ONE_MOD_Q
        )
        self.assertTrue(proof.is_valid(message, keypair.public_key, ONE_MOD_Q))
        self.assertFalse(bad_proof.is_valid(message, keypair.public_key, ONE_MOD_Q))

    @settings(
        deadline=timedelta(milliseconds=2000),
        suppress_health_check=[HealthCheck.too_slow],
        max_examples=10,
    )
    @given(
        elgamal_keypairs("keypair"),
        elements_mod_q_no_zero("nonce"),
        elements_mod_q("seed"),
        integers(0, 100),
        integers(0, 100),
    )
    def test_ccp_proof_known_constant(
        self,
        keypair: ElGamalKeyPair,
        nonce: ElementModQ,
        seed: ElementModQ,
        constant: int,
        bad_constant: int,
    ):
        # assume() slows down the test-case generation
        # so assume(constant != bad_constant)
        if constant == bad_constant:
            bad_constant = constant + 1

        message = elgamal_encrypt(constant, nonce, keypair.public_key)
        message_bad = elgamal_encrypt(bad_constant, nonce, keypair.public_key)

        proof = make_constant_chaum_pedersen_proof_known_nonce(
            message, constant, nonce, keypair.public_key, seed, ONE_MOD_Q
        )
        self.assertTrue(
            proof.is_valid(
                message, keypair.public_key, ONE_MOD_Q, expected_constant=constant
            )
        )
        self.assertTrue(proof.is_valid(message, keypair.public_key, ONE_MOD_Q))
        self.assertFalse(
            proof.is_valid(
                message, keypair.public_key, ONE_MOD_Q, expected_constant=bad_constant
            )
        )

        proof_bad1 = make_constant_chaum_pedersen_proof_known_nonce(
            message_bad, constant, nonce, keypair.public_key, seed, ONE_MOD_Q
        )
        self.assertFalse(
            proof_bad1.is_valid(message_bad, keypair.public_key, ONE_MOD_Q)
        )

        proof_bad2 = make_constant_chaum_pedersen_proof_known_nonce(
            message, bad_constant, nonce, keypair.public_key, seed, ONE_MOD_Q
        )
        self.assertFalse(proof_bad2.is_valid(message, keypair.public_key, ONE_MOD_Q))

    @settings(
        deadline=timedelta(milliseconds=2000),
        suppress_health_check=[HealthCheck.too_slow],
        max_examples=10,
    )
    @given(
        elgamal_keypairs("keypair"),
        elements_mod_q_no_zero("nonce"),
        elements_mod_q("seed"),
        integers(0, 100),
        integers(0, 100),
    )
    def test_ccp_proof_known_secret_key(
        self,
        keypair: ElGamalKeyPair,
        nonce: ElementModQ,
        seed: ElementModQ,
        constant: int,
        bad_constant: int,
    ):
        # assume() slows down the test-case generation
        # so assume(constant != bad_constant)
        if constant == bad_constant:
            bad_constant = constant + 1

            message = elgamal_encrypt(constant, nonce, keypair.public_key)
            bad_message = elgamal_encrypt(bad_constant, nonce, keypair.public_key)

            proof = make_constant_chaum_pedersen_proof_known_secret_key(
                message, constant, keypair.secret_key, seed, ONE_MOD_Q
            )
            self.assertTrue(
                proof.is_valid(
                    message, keypair.public_key, ONE_MOD_Q, expected_constant=constant
                )
            )
            self.assertTrue(proof.is_valid(message, keypair.public_key, ONE_MOD_Q))
            self.assertFalse(
                proof.is_valid(
                    message,
                    keypair.public_key,
                    ONE_MOD_Q,
                    expected_constant=bad_constant,
                )
            )
            self.assertFalse(proof.is_valid(bad_message, keypair.public_key, ONE_MOD_Q))

            bad_proof = make_constant_chaum_pedersen_proof_known_secret_key(
                bad_message, constant, keypair.secret_key, seed, ONE_MOD_Q
            )
            self.assertFalse(
                bad_proof.is_valid(
                    bad_message,
                    keypair.public_key,
                    ONE_MOD_Q,
                    expected_constant=constant,
                )
            )

            bad_proof2 = make_constant_chaum_pedersen_proof_known_secret_key(
                message, bad_constant, keypair.secret_key, seed, ONE_MOD_Q
            )
            self.assertFalse(
                bad_proof2.is_valid(
                    bad_message,
                    keypair.public_key,
                    ONE_MOD_Q,
                    expected_constant=constant,
                )
            )

            bad_proof3 = proof._replace(constant=sys.maxsize)
            self.assertFalse(
                bad_proof3.is_valid(message, keypair.public_key, ONE_MOD_Q)
            )


class TestGenericChaumPedersen(TestCase):
    @settings(
        deadline=timedelta(milliseconds=2000),
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(
        elements_mod_q("q1"),
        elements_mod_q("q2"),
        elements_mod_q("x"),
        elements_mod_q("notx"),
        elements_mod_q("seed"),
        elements_mod_q("hash_header"),
    )
    def test_gcp_proof(
        self,
        q1: ElementModQ,
        q2: ElementModQ,
        x: ElementModQ,
        notx: ElementModQ,
        seed: ElementModQ,
        hash_header: ElementModQ,
    ):
        # We need x != notx, and using assume() would slow down Hypothesis.
        if x == notx:
            notx = add_q(x, ONE_MOD_Q)

        self._helper_test_gcp(q1, q2, x, notx, seed, hash_header)

    def test_gcp_proof_simple(self) -> None:
        # Runs faster than the the Hypothesis version; useful when debugging.
        self._helper_test_gcp(
            TWO_MOD_Q, int_to_q(3), int_to_q(5), TWO_MOD_Q, ZERO_MOD_Q, None
        )
        self._helper_test_gcp(
            ONE_MOD_Q, ONE_MOD_Q, ZERO_MOD_Q, ONE_MOD_Q, ZERO_MOD_Q, None
        )

    def _helper_test_gcp(
        self,
        q1: ElementModQ,
        q2: ElementModQ,
        x: ElementModQ,
        notx: ElementModQ,
        seed: ElementModQ,
        hash_header: Optional[ElementModQ],
    ) -> None:
        g = g_pow_p(q1)
        h = g_pow_p(q2)
        gx = pow_p(g, x)
        hx = pow_p(h, x)
        gnotx = pow_p(g, notx)
        hnotx = pow_p(h, notx)

        proof = make_chaum_pedersen_generic(g, h, x, seed, hash_header)
        self.assertTrue(proof.is_valid(g, gx, h, hx, hash_header))

        if gx != gnotx and hx != hnotx:
            # In the degenerate case where q1 or q2 == 0, then we'd have a problem:
            # g = 1, gx = 1, and gnotx = 1. Same thing for h, hx, hnotx. This means
            # swapping in gnotx for gx doesn't actually do anything.

            self.assertFalse(proof.is_valid(g, gnotx, h, hx, hash_header))
            self.assertFalse(proof.is_valid(g, gx, h, hnotx, hash_header))
            self.assertFalse(proof.is_valid(g, gnotx, h, hnotx, hash_header))

    @settings(
        deadline=timedelta(milliseconds=2000),
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(
        elements_mod_q_no_zero("q1"),
        elements_mod_q_no_zero("q2"),
        elements_mod_q("x"),
        elements_mod_q("notx"),
        elements_mod_q("c"),
        elements_mod_q("seed"),
        elements_mod_q("hash_header"),
    )
    def test_fake_gcp_proof_doesnt_validate(
        self,
        q1: ElementModQ,
        q2: ElementModQ,
        x: ElementModQ,
        notx: ElementModQ,
        c: ElementModQ,
        seed: ElementModQ,
        hash_header: ElementModQ,
    ):
        if x == notx:
            notx = add_q(x, ONE_MOD_Q)

        g = g_pow_p(q1)
        h = g_pow_p(q2)
        gx = pow_p(g, x)
        hnotx = pow_p(h, notx)

        bad_proof = make_fake_chaum_pedersen_generic(g, gx, h, hnotx, c, seed)
        self.assertTrue(
            bad_proof.is_valid(g, gx, h, hnotx, hash_header, check_c=False),
            "if we don't check c, the proof will validate",
        )
        self.assertFalse(
            bad_proof.is_valid(g, gx, h, hnotx, hash_header, check_c=True),
            "if we do check c, the proof will not validate",
        )
