# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from random import choice, randint

import pytest
from bitcointx.core import satoshi_to_coins, lx
from elementstx.core import CAsset
from click.testing import CliRunner

from cli_common import load_data_with_checking_hash, read_plandata
from creditor_cli import creditor
from debtor_cli import debtor
from lib.utils import SafeDerivation

from . import sync_rpc, wait_confirm
from .conftest import ParticipantsData

LIQUIDREGTEST_BITCOIN_ASSET = CAsset(
    lx("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225")
)


@pytest.fixture
def participants_data(rpc, rpc2, tmppath):  # type: ignore
    args = [
        "make",
        "-r",
        rpc.service_url,
    ]
    principal_amount = randint(1000, 1000000)
    principal_asset_addr = rpc.getnewaddress()
    rpc.sendtoaddress(
        principal_asset_addr,
        satoshi_to_coins(principal_amount),
        "",
        "",
        False,
        False,
        1,
        "CONSERVATIVE",
        LIQUIDREGTEST_BITCOIN_ASSET.to_hex(),
        False,
    )
    (principal_utxo,) = rpc.listunspent(0, 3, [principal_asset_addr], False)

    collateral_amount = randint(1000, 1000000)
    collateral_issue = rpc.issueasset(satoshi_to_coins(collateral_amount), 0)
    rate_due = "2"
    rate_early = "0.1"
    num_blocks_in_period = randint(1, 30)
    rates_late = ("5.0", "7.5")
    M = len(rates_late)+1
    N = randint(4, 10)  # for some tests we need several periods
    S = randint(max(N, M)+1, N+M)
    # if principal will be with change
    plan_principal_amount = choice(
        (principal_amount // 10, randint(10, principal_amount // 10))
    )
    plan_collateral_amount = choice(
        (collateral_amount // 10, randint(10, collateral_amount // 10))
    )
    collateral_amount_unconditionally_forfeited = min(
        1, plan_collateral_amount//8
    )
    rate_collateral_penalty = "10"
    args.extend(
        (
            "--principal-asset",
            LIQUIDREGTEST_BITCOIN_ASSET.to_hex(),
            "--principal-amount",
            str(plan_principal_amount),
            "--collateral-asset",
            collateral_issue["asset"],
            "--collateral-amount",
            str(plan_collateral_amount),
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
            str(tmppath / "principal_info"),
            "--output-plan",
            str(tmppath / "plan"),
        )
    )
    runner = CliRunner()
    with SafeDerivation():
        runner.invoke(creditor, args)
    args = [
        "make",
        "-r",
        rpc.service_url,
    ]
    args.extend(
        (
            "--principal-asset",
            LIQUIDREGTEST_BITCOIN_ASSET.to_hex(),
            "--principal-amount",
            str(plan_principal_amount),
            "--collateral-asset",
            collateral_issue["asset"],
            "--collateral-amount",
            str(plan_collateral_amount),
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
            str(tmppath / "plan"),
        )
    )
    with SafeDerivation():
        runner.invoke(debtor, args)

    rpc.generate_block()

    plan_file_str = str(tmppath / "plan")
    plandata = read_plandata(plan_file_str)
    principal_info_file_str = str(tmppath / "principal_info")
    principaldata = load_data_with_checking_hash(principal_info_file_str)
    collateral_info_file_str = str(tmppath / "collateral_info")
    collateraldata = load_data_with_checking_hash(collateral_info_file_str)
    sync_rpc(rpc, rpc2)
    return ParticipantsData(plandata, principaldata, collateraldata)


def test_debtpay(  # type: ignore
    tmppath,
    rpc,
    contract_data,
    checkresult,
    mocker
):
    runner = CliRunner()
    plan_file_str = str(tmppath / "plan")
    debtor_data_str = str(tmppath / "debtor")
    args = [
        "paydebt",
        "-r",
        rpc.service_url,
        "-p",
        plan_file_str,
        "-d",
        debtor_data_str,
        "--force",
    ]
    mocker.patch("cli_common.wait_confirm", wait_confirm)
    with SafeDerivation():
        result = runner.invoke(debtor, args)
        checkresult(result)


def test_debtpayfull(  # type: ignore
    tmppath,
    rpc,
    contract_data,
    checkresult,
    mocker
):
    runner = CliRunner()
    plan_file_str = str(tmppath / "plan")
    debtor_data_str = str(tmppath / "debtor")
    args = [
        "paydebt",
        "-r",
        rpc.service_url,
        "-p",
        plan_file_str,
        "-d",
        debtor_data_str,
        "--full",
        "--force",
    ]
    mocker.patch("cli_common.wait_confirm", wait_confirm)
    with SafeDerivation():
        result = runner.invoke(debtor, args)
        checkresult(result)


def test_debtpay_partial_confirm_and_send(  # type: ignore
    tmppath, rpc, contract_data, checkresult, mocker
):
    runner = CliRunner()
    plan_file_str = str(tmppath / "plan")
    debtor_data_str = str(tmppath / "debtor")
    args = [
        "paydebt",
        "-r",
        rpc.service_url,
        "-p",
        plan_file_str,
        "-d",
        debtor_data_str,
    ]
    mocker.patch("cli_common.wait_confirm", wait_confirm)
    with SafeDerivation():
        result = runner.invoke(debtor, args, input="yes\nyes")
        checkresult(result)


def test_debtpay_full_confirm_and_send(  # type: ignore
    tmppath, rpc, contract_data, checkresult, mocker
):
    runner = CliRunner()
    plan_file_str = str(tmppath / "plan")
    debtor_data_str = str(tmppath / "debtor")
    args = [
        "paydebt",
        "-r",
        rpc.service_url,
        "-p",
        plan_file_str,
        "-d",
        debtor_data_str,
        "--full",
    ]
    mocker.patch("cli_common.wait_confirm", wait_confirm)
    with SafeDerivation():
        result = runner.invoke(debtor, args, input="yes\nyes")
        checkresult(result)
