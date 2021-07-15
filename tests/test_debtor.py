# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from decimal import Decimal
from random import randint

from bitcointx import ChainParams
from bitcointx.core import satoshi_to_coins, x
from bitcointx.core.key import CKey
from elementstx.core import CElementsTransaction

from click.testing import CliRunner

from cli_common import load_data_with_checking_hash, read_plandata
from debtor_cli import debtor

from lib.utils import SafeDerivation

from . import sync_rpc


def test_make_plan(tmppath, rpc, rpc2, checkresult):  # type: ignore
    runner = CliRunner()
    args = [
        "make",
        "-r",
        rpc.service_url,
    ]
    principal_amount = randint(100, 100000)
    principal_issue = rpc.issueasset(satoshi_to_coins(principal_amount), 0)
    collateral_amount = randint(100, 100000)
    collateral_amount_unconditionally_forfeited = collateral_amount//5
    collateral_issue = rpc.issueasset(satoshi_to_coins(collateral_amount), 0)
    rate_due = "2"
    rate_early = "0.1"
    num_blocks_in_period = randint(1, 10)
    rates_late = ("5.0", "7.5")
    M = len(rates_late)+1
    N = randint(1, 10)
    S = randint(max(N, M)+1, N+M)
    rate_collateral_penalty = "10"

    plan_file_str = str(tmppath / "plan")

    args.extend(
        (
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
            "--output-info",
            str(tmppath / "collateral_info"),
            "--output-plan",
            plan_file_str
        )
    )

    with SafeDerivation():
        result = runner.invoke(debtor, args)
        checkresult(result)
    rpc.generate_block()

    sync_rpc(rpc, rpc2)

    # checking generated files
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
    collateral_info_file_str = str(tmppath / "collateral_info")
    collateraldata = load_data_with_checking_hash(collateral_info_file_str)
    txstr = rpc.getrawtransaction(collateraldata["txid"])
    with ChainParams("elements"):
        blinding_key = CKey(x(collateraldata["blinding_key"]))
        index = collateraldata["vout_index"]
        tx = CElementsTransaction.deserialize(x(txstr))
        unblind_result = tx.vout[index].unblind_confidential_pair(
            blinding_key, tx.wit.vtxoutwit[index].rangeproof
        )
    assert not unblind_result.error
    assert unblind_result.amount == collateral_amount
