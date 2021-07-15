# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import os
import traceback
from random import choice, randint
from typing import Dict, Any

import pytest
from attr import attrs
from bitcointx.core import satoshi_to_coins
from bitcointx.core.key import CKey
from bitcointx.wallet import P2WPKHCoinAddress
from click.testing import CliRunner
from elementstx.wallet import CCoinConfidentialAddress

from cli_common import load_data_with_checking_hash, read_plandata
from creditor_cli import creditor
from debtor_cli import debtor
from facilitator_cli import facilitator
from lib.types import PlanData
from lib.types import ElementsRPCCaller as libReconnectingRPCCaller
from lib.utils import SafeDerivation

from . import sync_rpc, wait_confirm


@attrs(auto_attribs=True)
class ParticipantsData:
    plan: PlanData
    principal: Dict[str, Any]
    collateral: Dict[str, Any]


class ElementsRPCCaller(libReconnectingRPCCaller):
    def __init__(self, service_url: str) -> None:
        self.service_url = service_url
        super().__init__(service_url=service_url)

    def _get_random_addr(self) -> CCoinConfidentialAddress:
        blinding_key = CKey.from_secret_bytes(os.urandom(32))
        key = CKey.from_secret_bytes(os.urandom(32))
        addr = CCoinConfidentialAddress.from_unconfidential(
            P2WPKHCoinAddress.from_pubkey(key.pub), blinding_key.pub
        )
        return addr

    def generate_block(self) -> None:
        """Genearte one block"""
        self.generatetoaddress(1, str(self._get_random_addr()))


SERVICE_URL1 = "http://user1:password1@localhost:18884"
SERVICE_URL2 = "http://user2:password2@localhost:18885"


@pytest.fixture(scope="module")
def rpc() -> ElementsRPCCaller:
    return ElementsRPCCaller(service_url=SERVICE_URL1)


@pytest.fixture(scope="module")
def rpc2() -> ElementsRPCCaller:
    return ElementsRPCCaller(service_url=SERVICE_URL2)


@pytest.fixture
def tmppath(tmp_path, capsys):  # type: ignore
    with capsys.disabled():
        print(f"\ndir path which contains data: {tmp_path}")
    return tmp_path


@pytest.fixture
def checkresult(capsys):  # type: ignore
    def _checkresult(result):  # type: ignore
        with capsys.disabled():
            print(f"Output: {result.output}")
            if result.exit_code:
                if result.exc_info is not None:
                    traceback.print_tb(result.exc_info[2])
                    raise result.exc_info[1]

    return _checkresult


@pytest.fixture
def participants_data(rpc, rpc2, tmppath):  # type: ignore
    args = [
        "make",
        "-r",
        SERVICE_URL1,
    ]
    principal_amount = randint(1000, 1000000)
    principal_issue = rpc.issueasset(satoshi_to_coins(principal_amount), 0)
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
        1, plan_collateral_amount//9
    )
    rate_collateral_penalty = "10"
    args.extend(
        (
            "--principal-asset",
            principal_issue["asset"],
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
        SERVICE_URL1,
    ]
    args.extend(
        (
            "--principal-asset",
            principal_issue["asset"],
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


@pytest.fixture
def contract_data(  # type: ignore
    rpc, rpc2, tmppath, participants_data, checkresult, capsys, mocker
):
    runner = CliRunner()
    principal_info_file_str = str(tmppath / "principal_info")
    collateral_info_file_str = str(tmppath / "collateral_info")
    plan_file_str = str(tmppath / "plan")
    contract_start_delay = 5
    args = [
        "make",
        "-r",
        SERVICE_URL2,
        "-p",
        plan_file_str,
        "-l",
        principal_info_file_str,
        "-c",
        collateral_info_file_str,
        "--output-creditor",
        str(tmppath / "creditor"),
        "--output-debtor",
        str(tmppath / "debtor"),
        "--output-tx",
        str(tmppath / "loan_tx"),
        "--contract-start-delay",
        str(contract_start_delay)
    ]

    mocker.patch("lib.rpc_utils.wait_confirm", wait_confirm)

    with SafeDerivation():
        result = runner.invoke(facilitator, args)
        checkresult(result)
    # for confirm revocation asset
    rpc.generate_block()
    sync_rpc(rpc, rpc2)
    rpc2.generate_block()
    sync_rpc(rpc, rpc2)
    creditor_data_str = str(tmppath / "creditor")
    creditor_witness_path_str = str(tmppath / "creditor_witness")
    args = [
        "sign",
        "-r",
        SERVICE_URL1,
        "-p",
        plan_file_str,
        "-d",
        creditor_data_str,
        "-o",
        creditor_witness_path_str,
    ]
    with SafeDerivation():
        result = runner.invoke(creditor, args)
        checkresult(result)
    debtor_data_str = str(tmppath / "debtor")
    debtor_witness_path_str = str(tmppath / "debtor_witness")
    args = [
        "sign",
        "-r",
        SERVICE_URL1,
        "-p",
        plan_file_str,
        "-d",
        debtor_data_str,
        "-o",
        debtor_witness_path_str,
    ]
    with SafeDerivation():
        result = runner.invoke(debtor, args)
        checkresult(result)
    loan_tx_str = str(tmppath / "loan_tx")
    args = [
        "sign",
        "-r",
        SERVICE_URL2,
        "-t",
        loan_tx_str,
        "-c",
        creditor_witness_path_str,
        "-d",
        debtor_witness_path_str,
        "-o",
        str(tmppath / "signed_tx"),
    ]

    with SafeDerivation():
        result = runner.invoke(facilitator, args)
        checkresult(result)

    with open(str(tmppath / "signed_tx")) as f:
        tx_str = f.read()

    for _ in range(contract_start_delay):
        rpc.generate_block()
        sync_rpc(rpc, rpc2)

    txid = rpc.sendrawtransaction(tx_str)
    rpc.generate_block()
    sync_rpc(rpc, rpc2)
    with capsys.disabled():
        print(f"contract transaction was sent txid = {txid}")
    return participants_data
