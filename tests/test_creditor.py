# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import os

from decimal import Decimal
from random import randint

from typing import Any

import click
import pytest
from bitcointx import ChainParams
from bitcointx.core import satoshi_to_coins, x
from bitcointx.core.key import CKey
from bitcointx.rpc import JSONRPCError
from click.testing import CliRunner
from elementstx.core import CElementsTransaction, CAsset

from lib.utils import SafeDerivation

from cli_common import (
    asset_amount_is_enough, load_data_with_checking_hash, read_plandata
)
from creditor_cli import creditor

from . import sync_rpc


def test_asset_amount_is_enough_ok() -> None:
    class Rpc:
        def getbalance(self, *args: Any) -> str:
            return "0.00017903"

    result = asset_amount_is_enough(Rpc(), 900, CAsset(os.urandom(32)))  # type: ignore # noqa
    assert result
    result = asset_amount_is_enough(Rpc(), 17903, CAsset(os.urandom(32)))  # type: ignore # noqa
    assert result
    result = asset_amount_is_enough(Rpc(), 900000, CAsset(os.urandom(32)))  # type: ignore # noqa
    assert not result


def test_asset_amount_is_enough_rpc_broken() -> None:
    class Rpc:
        def getbalance(self, *args: Any) -> str:
            raise JSONRPCError({"code": 0, "message": "message"})

    with pytest.raises(click.ClickException, match=r"Can't get balance.*"):
        asset_amount_is_enough(Rpc(), 1000, CAsset(os.urandom(32)))  # type: ignore # noqa


def test_asset_amount_is_enough_rpc_return_wrong() -> None:
    class Rpc:
        def getbalance(self, *args: Any) -> str:
            return "abc"

    with pytest.raises(
        click.ClickException, match=r"Can't parse balance from rpc daemon abc"
    ):
        asset_amount_is_enough(Rpc(), 1000, CAsset(os.urandom(32)))  # type: ignore # noqa


def test_make_plan(tmppath, rpc, rpc2, checkresult):  # type: ignore
    runner = CliRunner()
    args = [
        "make",
        "-r",
        "http://user1:password1@localhost:18884",
    ]
    principal_amount = randint(100, 100000)
    principal_issue = rpc.issueasset(satoshi_to_coins(principal_amount), 0)
    collateral_amount = randint(100, 100000)
    collateral_issue = rpc.issueasset(satoshi_to_coins(collateral_amount), 0)
    rate_due = "2"
    rate_early = "0.1"
    num_blocks_in_period = randint(1, 10)
    rates_late = ("5.0", "7.5")
    M = len(rates_late)+1
    N = randint(1, 10)
    S = randint(max(N, M)+1, N+M)
    rate_collateral_penalty = "10"
    collateral_amount_unconditionally_forfeited = collateral_amount//5
    args.extend(
        [
            "--principal-asset",
            principal_issue["asset"],
            "--principal-amount",
            str(principal_amount),
            "--collateral-asset",
            collateral_issue["asset"],
            "--collateral-amount",
            str(collateral_amount),
            "--collateral-amount-unconditionally-forfeited",
            str(collateral_amount_unconditionally_forfeited),
            "--total-periods",
            str(N),
            "--total-steps",
            str(S),
            "--rate-due",
            str(rate_due),
            "--rate-early",
            str(rate_early),
            "--num-blocks-in-period",
            str(num_blocks_in_period),
            "--rates-late",
            ",".join(str(rl) for rl in rates_late),
            "--rate-collateral-penalty",
            str(rate_collateral_penalty),
            "--output-plan",
            str(tmppath / "plan"),
            "--output-info",
            str(tmppath / "principal_info"),
        ]
    )

    with SafeDerivation():
        result = runner.invoke(creditor, args)
        checkresult(result)

    rpc.generate_block()
    sync_rpc(rpc, rpc2)

    # checking generated files
    plan_file_str = str(tmppath / "plan")
    plandata = read_plandata(plan_file_str)
    assert plandata.principal_amount == principal_amount
    assert plandata.principal_asset.to_hex() == principal_issue["asset"]
    assert plandata.collateral_amount == collateral_amount
    assert plandata.collateral_asset.to_hex() == collateral_issue["asset"]
    assert (plandata.amount_C_uncond
            == collateral_amount_unconditionally_forfeited)
    assert plandata.rates.rate_due == Decimal(rate_due)
    assert plandata.rates.rate_early == Decimal(rate_early)
    assert (plandata.rates.rate_collateral_penalty
            == Decimal(rate_collateral_penalty))
    assert plandata.num_blocks_in_period == num_blocks_in_period
    assert plandata.N == N
    assert plandata.S == S
    assert plandata.rates.rates_late == [Decimal(value)
                                         for value in rates_late]
    principal_info_file_str = str(tmppath / "principal_info")
    principaldata = load_data_with_checking_hash(principal_info_file_str)
    txstr = rpc.getrawtransaction(principaldata["txid"])
    with ChainParams("elements"):
        blinding_key = CKey(x(principaldata["blinding_key"]))
        index = principaldata["vout_index"]
        tx = CElementsTransaction.deserialize(x(txstr))
        unblind_result = tx.vout[index].unblind_confidential_pair(
            blinding_key, tx.wit.vtxoutwit[index].rangeproof
        )
    assert not unblind_result.error
    assert unblind_result.amount == principal_amount
