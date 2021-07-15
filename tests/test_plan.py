# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import re
from typing import List, Any
from decimal import Decimal
from pathlib import Path

import pytest
from attr import attrs
from elementstx.core import CAsset

from lib.types import (
    PlanData, LateralProgressionStage, VerticalProgressionStage, Rates
)


def get_testdata() -> List[Path]:
    current_dir = Path(__file__).parent.absolute()
    return list((current_dir / "data").glob("*"))


@attrs(auto_attribs=True)
class Line:
    path: str
    total_repaid: int
    n: int
    m: int
    ident: str
    block: int

    @staticmethod
    def from_line(line: str) -> 'Line':
        ident = line[3:5]
        if ident == "RR":
            match = re.match(
                r"<<\"(?P<ident>.*?)\","  # ident
                r" *(?P<block>\d+),"  # num block
                r" *(?P<n>\d+),"  # state n
                r" *(?P<m>\d+),"  # state m
                r" *\"(?P<path>.*?)\","  # path
                r" *(?P<body_amount>\d+),"  # body
                r" *(?P<regular_repayment>\d+),"  # RegularRepayment
                r" *(?P<total_repaid>\d+),"  # total_repaid
                ".*TRUE",
                line,
            )
            assert match is not None
            return LineRR(
                path=match["path"],
                total_repaid=int(match["total_repaid"]),
                regular_repayment=int(match["regular_repayment"]),
                body_amount=int(match["body_amount"]),
                n=int(match["n"]),
                m=int(match["m"]),
                ident=match["ident"],
                block=int(match["block"]),
            )
        if ident == "RF":
            match = re.match(
                r"<<\"(?P<ident>.*?)\","  # ident
                r" *(?P<block>\d+),"  # num block
                r" *(?P<n>\d+),"  # state n
                r" *(?P<m>\d+),"  # state m
                r" *\"(?P<path>.*?)\","  # path
                r" *(?P<RegularRepayment>\d+),"  # RegularRepayment
                r" *(?P<total_repaid>\d+),"  # total_repaid
                ".*TRUE",
                line,
            )
            assert match is not None
            return LineRF(
                path=match["path"],
                total_repaid=int(match["total_repaid"]),
                regular_repayment=int(match["RegularRepayment"]),
                n=int(match["n"]),
                m=int(match["m"]),
                ident=match["ident"],
                block=int(match["block"]),
            )
        if ident == "ER":
            match = re.match(
                r"<<\"(?P<ident>.*?)\","  # ident
                r" *(?P<block>\d+),"  # num block
                r" *(?P<n>\d+),"  # state n
                r" *(?P<m>\d+),"  # state m
                r" *\"(?P<path>.*?)\","  # path
                r" *(?P<early_repayment>\d+),"  # Early Repayment
                r" *(?P<total_repaid>\d+),"  # total repaid
                ".*TRUE",
                line,
            )
            assert match is not None
            return LineER(
                path=match["path"],
                total_repaid=int(match["total_repaid"]),
                early_repayment=int(match["early_repayment"]),
                n=int(match["n"]),
                m=int(match["m"]),
                ident=match["ident"],
                block=int(match["block"]),
            )
        if ident == "CF":
            match = re.match(
                r"<<\"(?P<ident>.*?)\","  # ident
                r" *(?P<block>\d+),"  # num block
                r" *(?P<n>\d+),"  # state n
                r" *(?P<m>\d+),"  # state m
                r" *\"(?P<path>.*?)\","  # path
                r" *(?P<regular_repayment>\d+),"  # RegularRepayment
                r" *(?P<penalty>\d+),"  # Penalty
                r" *(?P<total_repaid>\d+),"  # total_repaid
                r" *\[Creditor.* (?P<cr_amount>\d+),"  # collateral to creditor
                r" *Debtor_D.* (?P<db_amount>\d+)\]"  # collateral to creditor
                ".*TRUE",
                line,
            )
            assert match is not None
            return LineCF(
                path=match["path"],
                total_repaid=int(match["total_repaid"]),
                regular_repayment=int(match["regular_repayment"]),
                penalty=int(match["penalty"]),
                collateral_to_creditor=int(match["cr_amount"]),
                collateral_to_debtor=int(match["db_amount"]),
                n=int(match["n"]),
                m=int(match["m"]),
                ident=match["ident"],
                block=int(match["block"]),
            )
        assert 0, "Unknown type"


@attrs(auto_attribs=True)
class LineCF(Line):
    regular_repayment: int
    penalty: int
    collateral_to_creditor: int
    collateral_to_debtor: int


@attrs(auto_attribs=True)
class LineRF(Line):
    regular_repayment: int


@attrs(auto_attribs=True)
class LineRR(Line):
    regular_repayment: int
    body_amount: int


@attrs(auto_attribs=True)
class LineER(Line):
    early_repayment: int


def get_stage_by_path(vstage: VerticalProgressionStage, path: str
                      ) -> VerticalProgressionStage:
    if path == "":
        return vstage

    if path[0] == ">":
        assert vstage.next_lateral_stage is not None
        return get_stage_by_path(vstage.next_lateral_stage.vertical_stages[0],
                                 path[1:])

    next_vstage = vstage.parent_lateral_stage.vertical_stages[
        vstage.index_m + 1
    ]

    if path[0] in ("v", "!"):
        return get_stage_by_path(next_vstage, path[1:])

    assert 0, f"Unknown {path[0]} path symbol"


def validate_line(first_lstage: LateralProgressionStage, line_str: str
                  ) -> None:
    line = Line.from_line(line_str)
    vstage = get_stage_by_path(
        first_lstage.vertical_stages[0], line.path[:-1])
    parent_lstage = vstage.parent_lateral_stage

    if isinstance(line, LineRR):
        assert vstage.next_lateral_stage is not None
        next_lstage = vstage.next_lateral_stage
        assert (
            line.regular_repayment == vstage.regular_repayment_amount
        ), (f"level={vstage.parent_lateral_stage.level_n}, "
            f"index={vstage.index_m}")
        assert (
            line.body_amount == next_lstage.B
        ), f"level={next_lstage.level_n}, index={vstage.index_m}"
        assert (
            line.total_repaid == next_lstage.total_repaid
        ), f"level={next_lstage.level_n}"
    elif isinstance(line, LineRF):
        assert (
            line.regular_repayment == vstage.regular_repayment_amount
        ), (f"level={vstage.parent_lateral_stage.level_n}, "
            f"index={vstage.index_m}")
        assert (
            line.total_repaid
            == parent_lstage.total_repaid + vstage.regular_repayment_amount
        ), f"level={parent_lstage.level_n}, index={vstage.index_m}"
    elif isinstance(line, LineER):
        assert (
            line.total_repaid
            == parent_lstage.total_repaid + vstage.early_repayment_amount
        ), f"level={parent_lstage.level_n}, index={vstage.index_m}"
        assert (
            line.early_repayment == vstage.early_repayment_amount
        ), (f"level={vstage.parent_lateral_stage.level_n}, "
            f"index={vstage.index_m}")
    elif isinstance(line, LineCF):
        assert (
            line.regular_repayment == vstage.regular_repayment_amount
        ), (f"level={vstage.parent_lateral_stage.level_n}, "
            f"index={vstage.index_m}")
        assert (
            line.total_repaid == parent_lstage.total_repaid
        ), f"level={parent_lstage.level_n}"
        assert (
            line.penalty ==
            vstage.amount_for_collateral_forfeiture_penalty
        ), f"level={parent_lstage.level_n}, index={vstage.index_m}"
    else:
        assert 0, f"Unknown line type {type(line)}"


@pytest.mark.parametrize("file", get_testdata())
def test_plan(file: Path, capsys: Any) -> None:
    (
        principal_amount_str,
        collateral_amount_str,
        total_periods_str,
        total_steps_str,
        rate_due_str,
        rate_early_str,
        rate_collateral_penalty_str,
        *rates_late_strs,
    ) = file.name.split("_")
    rates_late = [
        Decimal(rate) / Decimal(100) for rate in rates_late_strs
    ]
    rate_due = Decimal(rate_due_str) / Decimal(100)
    rate_early = Decimal(rate_early_str) / Decimal(100)
    rate_collateral_penalty = (
        Decimal(rate_collateral_penalty_str) / Decimal(100)
    )
    N = int(total_periods_str)
    S = int(total_steps_str)
    principal_amount = int(principal_amount_str)
    collateral_amount = int(collateral_amount_str)
    asset = CAsset(b"0" * 32)
    plandata = PlanData(
        principal_asset=asset,
        principal_amount=principal_amount,
        collateral_asset=asset,
        collateral_amount=collateral_amount,
        N=N,
        S=S,
        rates=Rates(rate_due=rate_due, rate_early=rate_early,
                    rate_collateral_penalty=rate_collateral_penalty,
                    rates_late=rates_late),
        num_blocks_in_period=4,
        amount_C_uncond=1
    )
    repayment_plan = plandata.to_repayment_plan()

    with open(file) as f:
        for line in f:
            if not line.startswith("<<"):
                continue
            with capsys.disabled():  # type :ignore
                validate_line(repayment_plan.first_lateral_stage, line)
