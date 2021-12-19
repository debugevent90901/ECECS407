# Support for basic modular math in ElectionGuard. This code's primary purpose is to be "correct",
# in the sense that performance may be less than hand-optimized C code, and no guarantees are
# made about timing or other side-channels.
import pprint
from secrets import randbelow
from typing import Any, Final, Optional, Union, Sequence, List, NamedTuple

# working around a weird bug in mypy, where it doesn't see divm but sees the rest
from gmpy2 import divm  # type: ignore
from gmpy2 import mpz, powmod, to_binary, from_binary

Q: Final[int] = pow(2, 256) - 189
P: Final[
    int
] = 1044388881413152506691752710716624382579964249047383780384233483283953907971553643537729993126875883902173634017777416360502926082946377942955704498542097614841825246773580689398386320439747911160897731551074903967243883427132918813748016269754522343505285898816777211761912392772914485521155521641049273446207578961939840619466145806859275053476560973295158703823395710210329314709715239251736552384080845836048778667318931418338422443891025911884723433084701207771901944593286624979917391350564662632723703007964229849154756196890615252286533089643184902706926081744149289517418249153634178342075381874131646013444796894582106870531535803666254579602632453103741452569793905551901541856173251385047414840392753585581909950158046256810542678368121278509960520957624737942914600310646609792665012858397381435755902851312071248102599442308951327039250818892493767423329663783709190716162023529669217300939783171415808233146823000766917789286154006042281423733706462905243774854543127239500245873582012663666430583862778167369547603016344242729592244544608279405999759391099775667746401633668308698186721172238255007962658564443858927634850415775348839052026675785694826386930175303143450046575460843879941791946313299322976993405829119
R: Final[int] = ((P - 1) * pow(Q, -1, P)) % P
G: Final[
    int
] = 14245109091294741386751154342323521003543059865261911603340669522218159898070093327838595045175067897363301047764229640327930333001123401070596314469603183633790452807428416775717923182949583875381833912370889874572112086966300498607364501764494811956017881198827400327403252039184448888877644781610594801053753235453382508543906993571248387749420874609737451803650021788641249940534081464232937193671929586747339353451021712752406225276255010281004857233043241332527821911604413582442915993833774890228705495787357234006932755876972632840760599399514028393542345035433135159511099877773857622699742816228063106927776147867040336649025152771036361273329385354927395836330206311072577683892664475070720408447257635606891920123791602538518516524873664205034698194561673019535564273204744076336022130453963648114321050173994259620611015189498335966173440411967562175734606706258335095991140827763942280037063180207172918769921712003400007923888084296685269233298371143630883011213745082207405479978418089917768242592557172834921185990876960527013386693909961093302289646193295725135238595082039133488721800071459503353417574248679728577942863659802016004283193163470835709405666994892499382890912238098413819320185166580019604608311466
Q_MINUS_ONE: Final[int] = Q - 1

_P_gmp = mpz(P)
_Q_gmp = mpz(Q)
_G_gmp = mpz(G)
_0_gmp = mpz(0)
_1_gmp = mpz(1)
_2_gmp = mpz(2)

# The actual type would be more recursive, e.g., FormulaTypes = Union[str, Sequence[FormulaType]],
# but we can't express this in Python. Trying to get anything simpler to typecheck with MyPy is a pain
# and doesn't seem to be worth it, so we punt.
FormulaTypes = Any

_pp = pprint.PrettyPrinter(indent=4)


class ElementModQ(NamedTuple):
    """An element of the smaller `mod q` space, i.e., in [0, Q), where Q is a 256-bit prime."""

    elem: mpz
    formula: FormulaTypes

    def to_hex(self) -> str:
        """
        Converts from the element to the hex representation of bytes. This is preferable to directly
        accessing `elem`, whose representation might change.
        """
        h = format(self.elem, "02X")
        if len(h) % 2:
            h = "0" + h
        return h

    def to_int(self) -> int:
        """
        Converts from the element to a regular integer. This is preferable to directly
        accessing `elem`, whose representation might change.
        """
        return int(self.elem)

    def is_in_bounds(self) -> bool:
        """
        Validates that the element is actually within the bounds of [0,Q).
        Returns true if all is good, false if something's wrong.
        """
        return 0 <= self.elem < Q

    def is_in_bounds_no_zero(self) -> bool:
        """
        Validates that the element is actually within the bounds of [1,Q).
        Returns true if all is good, false if something's wrong.
        """
        return 0 < self.elem < Q

    # overload != (not equal to) operator
    def __ne__(self, other: Any) -> bool:
        return (
            isinstance(other, ElementModP) or isinstance(other, ElementModQ)
        ) and not eq_elems(self, other)

    # overload == (equal to) operator
    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ElementModP) or isinstance(other, ElementModQ)
        ) and eq_elems(self, other)

    def __repr__(self) -> str:
        return f"ElementModQ(formula = {self.formula}, elem = {self.elem.digits()})"

    def __str__(self) -> str:
        return self.__repr__()

    def __hash__(self) -> int:
        return hash(int(self.elem))

    def pretty_printed_formula(self) -> str:
        """
        Converts the attached formula to a nicely indented string.
        """
        return _pp.pformat(self.formula)

    def update_formula(self, formula: FormulaTypes) -> "ElementModQ":
        """
        Returns a copy of this element, but with the new formula
        """
        return self._replace(formula=formula)


class ElementModP(NamedTuple):
    """An element of the larger `mod p` space, i.e., in [0, P), where P is a 4096-bit prime."""

    elem: mpz
    formula: FormulaTypes

    def to_hex(self) -> str:
        """
        Converts from the element to the hex representation of bytes. This is preferable to directly
        accessing `elem`, whose representation might change.
        """
        h = format(self.elem, "02X")
        if len(h) % 2:
            h = "0" + h
        return h

    def to_int(self) -> int:
        """
        Converts from the element to a regular integer. This is preferable to directly
        accessing `elem`, whose representation might change.
        """
        return int(self.elem)

    def is_in_bounds(self) -> bool:
        """
        Validates that the element is actually within the bounds of [0,P).
        Returns true if all is good, false if something's wrong.
        """
        return 0 <= self.elem < P

    def is_in_bounds_no_zero(self) -> bool:
        """
        Validates that the element is actually within the bounds of [1,P).
        Returns true if all is good, false if something's wrong.
        """
        return 0 < self.elem < P

    def is_valid_residue(self) -> bool:
        """
        Validates that this element is in Z^r_p.
        Returns true if all is good, false if something's wrong.
        """
        residue = powmod(self.elem, _Q_gmp, _P_gmp)
        return self.is_in_bounds() and residue == _1_gmp

    # overload != (not equal to) operator
    def __ne__(self, other: Any) -> bool:
        return (
            isinstance(other, ElementModP) or isinstance(other, ElementModQ)
        ) and not eq_elems(self, other)

    # overload == (equal to) operator
    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ElementModP) or isinstance(other, ElementModQ)
        ) and eq_elems(self, other)

    def __repr__(self) -> str:
        return f"ElementModP(formula = {self.formula}, elem = {self.elem.digits()})"

    def __str__(self) -> str:
        return self.__repr__()

    def __hash__(self) -> int:
        return hash(int(self.elem))

    def pretty_printed_formula(self) -> str:
        """
        Converts the attached formula to a nicely indented string.
        """
        return _pp.pformat(self.formula)

    def update_formula(self, formula: FormulaTypes) -> "ElementModP":
        """
        Returns a copy of this element, but with the new formula
        """
        return self._replace(formula=formula)


# Common constants
ZERO_MOD_Q: Final[ElementModQ] = ElementModQ(_0_gmp, "0")
ONE_MOD_Q: Final[ElementModQ] = ElementModQ(_1_gmp, "1")
TWO_MOD_Q: Final[ElementModQ] = ElementModQ(_2_gmp, "2")

ZERO_MOD_P: Final[ElementModP] = ElementModP(_0_gmp, "0")
ONE_MOD_P: Final[ElementModP] = ElementModP(_1_gmp, "1")
TWO_MOD_P: Final[ElementModP] = ElementModP(_2_gmp, "2")
G_MOD_P: Final[ElementModP] = ElementModP(_G_gmp, "G")

ElementModPOrQ = Union[ElementModP, ElementModQ]


def int_to_q(
    input: Union[str, int], formula: FormulaTypes = ""
) -> Optional[ElementModQ]:
    """
    Given a Python integer, returns an ElementModQ.
    Returns `None` if the number is out of the allowed
    [0,Q) range.

    The optional formula parameter sets the symbolic value for
    this element. Normally, it's just the input, converted to
    a string.
    """
    i = int(input)
    if 0 <= i < Q:
        return ElementModQ(mpz(i), str(input) if formula == "" else formula)
    else:
        return None


def int_to_q_unchecked(
    input: Union[str, int], formula: FormulaTypes = ""
) -> ElementModQ:
    """
    Given a Python integer, returns an ElementModQ. Allows
    for the input to be out-of-bounds, and thus creating an invalid
    element (i.e., outside of [0,Q)). Useful for tests of it
    you're absolutely, positively, certain the input is in-bounds.

    The optional formula parameter sets the symbolic value for
    this element. Normally, it's just the input, converted to
    a string.
    """

    m = mpz(int(input))
    return ElementModQ(m, str(input) if formula == "" else formula)


def int_to_p(
    input: Union[str, int], formula: FormulaTypes = ""
) -> Optional[ElementModP]:
    """
    Given a Python integer, returns an ElementModP.
    Returns `None` if the number is out of the allowed
    [0,P) range.

    The optional formula parameter sets the symbolic value for
    this element. Normally, it's just the input, converted to
    a string.
    """
    i = int(input)
    if 0 <= i < P:
        return ElementModP(mpz(i), str(input) if formula == "" else formula)
    else:
        return None


def int_to_p_unchecked(
    input: Union[str, int], formula: FormulaTypes = ""
) -> ElementModP:
    """
    Given a Python integer, returns an ElementModP. Allows
    for the input to be out-of-bounds, and thus creating an invalid
    element (i.e., outside of [0,P)). Useful for tests or if
    you're absolutely, positively, certain the input is in-bounds.

    The optional formula parameter sets the symbolic value for
    this element. Normally, it's just the input, converted to
    a string.
    """
    m = mpz(int(input))
    return ElementModP(m, str(input) if formula == "" else formula)


def q_to_bytes(e: ElementModQ) -> bytes:
    """
    Returns a byte sequence from the element.
    """
    return to_binary(e.elem)


def bytes_to_q(b: bytes) -> ElementModQ:
    """
    Returns an element from a byte sequence.
    """
    return ElementModQ(mpz(from_binary(b)), "?")


def make_formula(
    operation: str, *formulas: Union[ElementModPOrQ, FormulaTypes]
) -> FormulaTypes:
    """
    Helper method to build formulas as we're doing math on group elements.
    """

    return [operation] + [
        x.formula
        if isinstance(x, ElementModP) or isinstance(x, ElementModQ)
        else x
        if isinstance(x, Sequence) or isinstance(x, List)
        else str(x)
        for x in formulas
    ]


def add_q(*elems: ElementModQ) -> ElementModQ:
    """
    Adds together one or more elements in Q, returns the sum mod Q.
    """
    t = _0_gmp
    for e in elems:
        t = (t + e.elem) % _Q_gmp

    return ElementModQ(t, make_formula("add_q", *elems))


def a_minus_b_q(a: ElementModQ, b: ElementModQ) -> ElementModQ:
    """
    Computes (a-b) mod q.
    """
    return ElementModQ((a.elem - b.elem) % _Q_gmp, make_formula("a_minus_b_q", a, b))


def div_p(a: ElementModPOrQ, b: ElementModPOrQ) -> ElementModP:
    """
    Computes a/b mod p
    """
    return ElementModP(divm(a.elem, b.elem, _P_gmp), make_formula("div_p", a, b))


def negate_q(a: ElementModQ) -> ElementModQ:
    """
    Computes (Q - a) mod q.
    """
    return ElementModQ(_Q_gmp - a.elem, make_formula("negate_q", a))


def a_plus_bc_q(a: ElementModQ, b: ElementModQ, c: ElementModQ) -> ElementModQ:
    """
    Computes (a + b * c) mod q.
    """
    return ElementModQ(
        (a.elem + b.elem * c.elem) % _Q_gmp, make_formula("a_plus_bc_q", a, b, c)
    )


def mult_inv_p(e: ElementModPOrQ) -> ElementModP:
    """
    Computes the multiplicative inverse mod p.

    :param e:  An element in [1, P).
    """
    assert e.elem != 0, "No multiplicative inverse for zero"

    # return ElementModP(powmod(e.elem, -1, P))
    return ElementModP(divm(1, e.elem, _P_gmp), make_formula("mult_inv_p", e))


def pow_p(b: ElementModPOrQ, e: ElementModPOrQ) -> ElementModP:
    """
    Computes b^e mod p.

    :param b: An element in [0,P).
    :param e: An element in [0,P).
    """

    return ElementModP(powmod(b.elem, e.elem, _P_gmp), make_formula("pow_p", b, e))


def mult_p(*elems: ElementModPOrQ) -> ElementModP:
    """
    Computes the product, mod p, of all elements.

    :param elems: Zero or more elements in [0,P).
    """
    product = _1_gmp
    for x in elems:
        product = (product * x.elem) % _P_gmp
    return ElementModP(product, make_formula("mult_p", *elems))


def g_pow_p(e: ElementModPOrQ) -> ElementModP:
    """
    Computes g^e mod p.

    :param e: An element in [0,P).
    """
    if e.elem == _0_gmp:
        return ONE_MOD_P

    if e.elem == _1_gmp:
        return G_MOD_P

    return ElementModP(powmod(_G_gmp, e.elem, _P_gmp), make_formula("g_pow_p", e))


def rand_q() -> ElementModQ:
    """
    Generate random number between 0 and Q

    :return: Random value between 0 and Q
    """
    return int_to_q_unchecked(randbelow(Q), formula=make_formula("rand_q"))


def rand_range_q(start: int) -> ElementModQ:
    """
    Generate random number between start and Q

    :param start: Starting value of range
    :return: Random value between start and Q
    """

    random = randbelow(int(Q - start)) + int(start)
    return int_to_q_unchecked(random, formula=make_formula("rand_range_q", str(start)))


def eq_elems(a: ElementModPOrQ, b: ElementModPOrQ) -> bool:
    """
    Returns whether the two elements hold the same value.
    """
    return a.elem == b.elem
