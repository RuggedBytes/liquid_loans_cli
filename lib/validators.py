# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import abc
from decimal import Decimal

# TODO: move constants in the separate file
MAX_TOTAL_PERIODS = 100
MIN_TOTAL_PERIODS = 1
MAX_NUM_BLOCKS_IN_PERIOD = 100
MIN_NUM_BLOCKS_IN_PERIOD = 1
MAX_RATE_VALUE = Decimal(1000)


class ValidationResult(abc.ABC):
    ...


class ValidationFailure(ValidationResult):
    def __init__(self, error: str) -> None:
        self.error = error


class ValidationSuccess(ValidationResult):
    ...


VALID = ValidationSuccess()


def validate_total_periods(
    total_periods: int,
) -> ValidationResult:
    if total_periods < MIN_TOTAL_PERIODS:
        return ValidationFailure(
            f"total-periods value must be greater than {MIN_TOTAL_PERIODS}"
        )
    if total_periods > MAX_TOTAL_PERIODS:
        return ValidationFailure(
            f"total-periods value must be below {MAX_TOTAL_PERIODS}"
        )
    return VALID


def validate_total_steps(
    S: int,
    N: int,
    M: int,
) -> ValidationResult:
    if S < max(M, N) + 1:
        return ValidationFailure(
            f"total-steps value must be greater than max(M,N) ({max(M, N)})"
        )

    if S > M + N:
        return ValidationFailure(
            f"total-steps value must be below M+N ({M+N})"
        )

    return VALID


def validate_num_blocks_in_period(
    num_bloks: int,
) -> ValidationResult:
    if num_bloks < MIN_NUM_BLOCKS_IN_PERIOD:
        return ValidationFailure(
            f"num-blocks-in-period value must be greater than"
            f" {MIN_NUM_BLOCKS_IN_PERIOD}"
        )
    if num_bloks > MAX_NUM_BLOCKS_IN_PERIOD:
        return ValidationFailure(
            f"num-blocks-in-period value must be below"
            f" {MAX_NUM_BLOCKS_IN_PERIOD}"
        )
    return VALID


def validate_rate(
    value: Decimal, name: str
) -> ValidationResult:

    if value < 0:
        return ValidationFailure(f"{name} value must be greater than 0")

    if value > MAX_RATE_VALUE:
        return ValidationFailure(
            f"{name} value must be below {MAX_RATE_VALUE}"
        )

    return VALID
