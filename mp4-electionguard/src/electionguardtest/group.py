from typing import TypeVar, Callable

from hypothesis.strategies import composite, integers, SearchStrategy

from electionguard.group import (
    Q,
    P,
    int_to_p_unchecked,
    int_to_q_unchecked,
)

_T = TypeVar("_T")
_DrawType = Callable[[SearchStrategy[_T]], _T]


@composite
def elements_mod_q(draw: _DrawType, variable_name: str = ""):
    """
    Generates an arbitrary element from [0,Q).

    :param draw: Hidden argument, used by Hypothesis.
    :param variable_name: Optional argument: specifies the formula name of this element
    """
    return int_to_q_unchecked(
        draw(integers(min_value=0, max_value=Q - 1)),
        formula=variable_name if variable_name != "" else "?",
    )


@composite
def elements_mod_q_no_zero(draw: _DrawType, variable_name: str = ""):
    """
    Generates an arbitrary element from [1,Q).

    :param draw: Hidden argument, used by Hypothesis.
    :param variable_name: Optional argument: specifies the formula name of this element
    """
    return int_to_q_unchecked(
        draw(integers(min_value=1, max_value=Q - 1)),
        formula=variable_name if variable_name != "" else "?",
    )


@composite
def elements_mod_p(draw: _DrawType, variable_name: str = ""):
    """
    Generates an arbitrary element from [0,P).

    :param draw: Hidden argument, used by Hypothesis.
    :param variable_name: Optional argument: specifies the formula name of this element
    """
    return int_to_p_unchecked(
        draw(integers(min_value=0, max_value=P - 1)),
        formula=variable_name if variable_name != "" else "?",
    )


@composite
def elements_mod_p_no_zero(draw: _DrawType, variable_name: str = ""):
    """
    Generates an arbitrary element from [1,P).

    :param draw: Hidden argument, used by Hypothesis.
    :param variable_name: Optional argument: specifies the formula name of this element
    """
    return int_to_p_unchecked(
        draw(integers(min_value=1, max_value=P - 1)),
        formula=variable_name if variable_name != "" else "?",
    )
