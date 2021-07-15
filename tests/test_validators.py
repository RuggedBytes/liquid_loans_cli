# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from decimal import Decimal
from random import randint

import pytest

from lib.validators import (
    MAX_NUM_BLOCKS_IN_PERIOD,
    MAX_RATE_VALUE,
    MAX_TOTAL_PERIODS,
    MIN_NUM_BLOCKS_IN_PERIOD,
    MIN_TOTAL_PERIODS,
    VALID,
    validate_num_blocks_in_period,
    validate_rate,
    validate_total_periods,
    validate_total_steps,
    ValidationFailure
)


@pytest.mark.parametrize("value", [-1, 0])
def test_validate_total_periods_below(value: int) -> None:
    result = validate_total_periods(value)
    assert isinstance(result, ValidationFailure)
    assert (
        result.error
        == f"total-periods value must be greater than {MIN_TOTAL_PERIODS}"
    )


def test_validate_total_periods_high() -> None:
    result = validate_total_periods(MAX_TOTAL_PERIODS + 1)
    assert isinstance(result, ValidationFailure)
    assert (
        result.error
        == f"total-periods value must be below {MAX_TOTAL_PERIODS}"
    )


def test_validate_total_steps_low() -> None:
    M = 2
    N = 2
    S = 1
    result = validate_total_steps(S, N, M)
    assert isinstance(result, ValidationFailure)
    assert (
        result.error
        == f"total-steps value must be greater than max(M,N) ({max(M, N)})"
    )


def test_validate_total_steps_high() -> None:
    M = 2
    N = 2
    S = 10
    result = validate_total_steps(S, N, M)
    assert isinstance(result, ValidationFailure)
    assert (
        result.error
        == f"total-steps value must be below M+N ({M+N})"
    )


def test_validate_total_periods() -> None:
    result = validate_total_periods(
        randint(MIN_TOTAL_PERIODS, MAX_TOTAL_PERIODS)
    )
    assert result is VALID


def test_validate_total_steps() -> None:
    total_periods = randint(MIN_TOTAL_PERIODS, MAX_TOTAL_PERIODS)
    num_rates = randint(1, 10)
    total_steps = randint(max(total_periods, num_rates)+1,
                          total_periods+num_rates)
    result = validate_total_steps(total_steps, total_periods, num_rates)
    assert result is VALID
    total_steps = 1

    result = validate_total_steps(total_steps, total_periods, num_rates)
    assert result is not VALID

    total_steps = total_periods + num_rates + 1
    result = validate_total_steps(total_steps, total_periods, num_rates)
    assert result is not VALID


@pytest.mark.parametrize("value", [-1, 0])
def test_validate_num_blocks_in_period_below(value: int) -> None:
    result = validate_num_blocks_in_period(value)
    assert isinstance(result, ValidationFailure)
    assert (
        result.error == f"num-blocks-in-period value must be greater than"
        f" {MIN_NUM_BLOCKS_IN_PERIOD}"
    )


def test_validate_num_blocks_in_period_high() -> None:
    result = validate_num_blocks_in_period(MAX_NUM_BLOCKS_IN_PERIOD + 1)
    assert isinstance(result, ValidationFailure)
    assert (
        result.error == f"num-blocks-in-period value must be below"
        f" {MAX_NUM_BLOCKS_IN_PERIOD}"
    )


def test_validate_num_blocks_in_period() -> None:
    result = validate_num_blocks_in_period(
        randint(MIN_NUM_BLOCKS_IN_PERIOD, MAX_NUM_BLOCKS_IN_PERIOD)
    )
    assert result is VALID


@pytest.mark.parametrize("value", [Decimal(-1), Decimal(-0.1)])
def test_validate_rate_below(value: Decimal) -> None:
    result = validate_rate(value, "")
    assert isinstance(result, ValidationFailure)
    assert result.error == " value must be greater than 0"


def test_validate_rate_high() -> None:
    result = validate_rate(MAX_RATE_VALUE + Decimal(1), "")
    assert isinstance(result, ValidationFailure)
    assert result.error == f" value must be below {MAX_RATE_VALUE}"


def test_validate_rate() -> None:
    result = validate_rate(Decimal(randint(0, 100)), "")
    assert result is VALID
