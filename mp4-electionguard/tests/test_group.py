import unittest

from hypothesis import given

from electionguard.group import (
    P,
    Q,
    R,
    G,
    ZERO_MOD_P,
    ZERO_MOD_Q,
    ONE_MOD_P,
    ONE_MOD_Q,
    G_MOD_P,
    ElementModP,
    ElementModQ,
    a_minus_b_q,
    mult_inv_p,
    mult_p,
    g_pow_p,
    int_to_p,
    int_to_q,
    add_q,
    div_p,
    a_plus_bc_q,
    int_to_p_unchecked,
    int_to_q_unchecked,
)
from electionguardtest.group import (
    elements_mod_p_no_zero,
    elements_mod_p,
    elements_mod_q,
    elements_mod_q_no_zero,
)


class TestEquality(unittest.TestCase):
    @given(elements_mod_q("q"), elements_mod_q("q2"))
    def testPsNotEqualToQs(self, q: ElementModQ, q2: ElementModQ):
        p = int_to_p_unchecked(q.to_int())
        p2 = int_to_p_unchecked(q2.to_int())

        # same value should imply they're equal
        self.assertEqual(p, q)
        self.assertEqual(q, p)

        if q.to_int() != q2.to_int():
            # these are genuinely different numbers
            self.assertNotEqual(q, q2)
            self.assertNotEqual(p, p2)
            self.assertNotEqual(q, p2)
            self.assertNotEqual(p, q2)

        # of course, we're going to make sure that a number is equal to itself
        self.assertEqual(p, p)
        self.assertEqual(q, q)


class TestModularArithmetic(unittest.TestCase):
    @given(elements_mod_q("q"))
    def test_add_q(self, q: ElementModQ):
        as_int = add_q(q, ONE_MOD_Q)
        as_elem = add_q(q, int_to_q_unchecked(1))
        self.assertEqual(as_int, as_elem)

    @given(elements_mod_q("q"))
    def test_a_plus_bc_q(self, q: ElementModQ):
        as_int = a_plus_bc_q(q, ONE_MOD_Q, ONE_MOD_Q)
        as_elem = a_plus_bc_q(q, int_to_q_unchecked(1), int_to_q_unchecked(1))
        self.assertEqual(as_int, as_elem)

    @given(elements_mod_q("q"))
    def test_a_minus_b_q(self, q: ElementModQ):
        as_int = a_minus_b_q(q, ONE_MOD_Q)
        as_elem = a_minus_b_q(q, int_to_q_unchecked(1))
        self.assertEqual(as_int, as_elem)

    @given(elements_mod_p("p"))
    def test_div_p(self, p: ElementModQ):
        as_int = div_p(p, ONE_MOD_Q)
        as_elem = div_p(p, int_to_p_unchecked(1))
        self.assertEqual(as_int, as_elem)

    def test_no_mult_inv_of_zero(self):
        self.assertRaises(Exception, mult_inv_p, ZERO_MOD_P)

    @given(elements_mod_p_no_zero("p"))
    def test_mult_inverses(self, elem: ElementModP):
        inv = mult_inv_p(elem)
        self.assertEqual(mult_p(elem, inv), ONE_MOD_P)

    @given(elements_mod_p("p"))
    def test_mult_identity(self, elem: ElementModP):
        self.assertEqual(elem, mult_p(elem))

    def test_mult_noargs(self):
        self.assertEqual(ONE_MOD_P, mult_p())

    def test_add_noargs(self):
        self.assertEqual(ZERO_MOD_Q, add_q())

    def test_properties_for_constants(self):
        self.assertNotEqual(G, 1)
        self.assertEqual((R * Q) % P, P - 1)
        self.assertLess(Q, P)
        self.assertLess(G, P)
        self.assertLess(R, P)

    def test_simple_powers(self):
        self.assertEqual(G_MOD_P, g_pow_p(ONE_MOD_Q))
        self.assertEqual(ONE_MOD_P, g_pow_p(ZERO_MOD_Q))

    @given(elements_mod_q("q"))
    def test_in_bounds_q(self, q: ElementModQ):
        self.assertTrue(q.is_in_bounds())
        too_big = q.to_int() + Q
        too_small = q.to_int() - Q
        self.assertFalse(int_to_q_unchecked(too_big).is_in_bounds())
        self.assertFalse(int_to_q_unchecked(too_small).is_in_bounds())
        self.assertEqual(None, int_to_q(too_big))
        self.assertEqual(None, int_to_q(too_small))

    @given(elements_mod_p("p"))
    def test_in_bounds_p(self, p: ElementModP):
        self.assertTrue(p.is_in_bounds())
        too_big = p.to_int() + P
        too_small = p.to_int() - P
        self.assertFalse(int_to_p_unchecked(too_big).is_in_bounds())
        self.assertFalse(int_to_p_unchecked(too_small).is_in_bounds())
        self.assertEqual(None, int_to_p(too_big))
        self.assertEqual(None, int_to_p(too_small))

    @given(elements_mod_q_no_zero("q"))
    def test_in_bounds_q_no_zero(self, q: ElementModQ):
        self.assertTrue(q.is_in_bounds_no_zero())
        self.assertFalse(ZERO_MOD_Q.is_in_bounds_no_zero())
        self.assertFalse(int_to_q_unchecked(q.to_int() + Q).is_in_bounds_no_zero())
        self.assertFalse(int_to_q_unchecked(q.to_int() - Q).is_in_bounds_no_zero())

    @given(elements_mod_p_no_zero("p"))
    def test_in_bounds_p_no_zero(self, p: ElementModP):
        self.assertTrue(p.is_in_bounds_no_zero())
        self.assertFalse(ZERO_MOD_P.is_in_bounds_no_zero())
        self.assertFalse(int_to_p_unchecked(p.to_int() + P).is_in_bounds_no_zero())
        self.assertFalse(int_to_p_unchecked(p.to_int() - P).is_in_bounds_no_zero())

    @given(elements_mod_q("q"))
    def test_large_values_rejected_by_int_to_q(self, q: ElementModQ):
        oversize = q.to_int() + Q
        self.assertEqual(None, int_to_q(oversize))
