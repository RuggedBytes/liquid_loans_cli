# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from click.testing import CliRunner

from creditor_cli import creditor
from debtor_cli import debtor

from lib.utils import SafeDerivation

from . import wait_confirm, sync_rpc


def test_mutual(tmppath, contract_data, rpc, rpc2, checkresult, mocker):  # type: ignore # noqa
    plan = contract_data.plan
    runner = CliRunner()

    for _ in range(5 + plan.num_blocks_in_period):
        rpc.generate_block()

    sync_rpc(rpc, rpc2)

    tx_data_file_str = str(tmppath / "tx_mutual_data")
    plan_file_str = str(tmppath / "plan")
    creditor_data_str = str(tmppath / "creditor")
    args = [
        "createmutual",
        "-r",
        rpc.service_url,
        "-p",
        plan_file_str,
        "-d",
        creditor_data_str,
        "--debt",
        plan.principal_amount // 2,
        "-o",
        tx_data_file_str,
    ]
    with SafeDerivation():
        result = runner.invoke(creditor, args)
        checkresult(result)
    mutual_tx_file_str = str(tmppath / "tx_mutual_signed_partially")
    debtor_data_str = str(tmppath / "debtor")
    args = [
        "updatemutual",
        "-r",
        rpc.service_url,
        "-p",
        plan_file_str,
        "-d",
        debtor_data_str,
        "--tx",
        tx_data_file_str,
        "-o",
        mutual_tx_file_str,
        "--force",
    ]
    with SafeDerivation():
        result = runner.invoke(debtor, args)
        checkresult(result)
    args = [
        "signmutual",
        "-r",
        rpc.service_url,
        "--debt",
        plan.principal_amount // 2,
        "--tx",
        mutual_tx_file_str,
        "--force",
    ]
    mocker.patch("cli_common.wait_confirm", wait_confirm)
    with SafeDerivation():
        result = runner.invoke(creditor, args)
        checkresult(result)


def test_mutual_confirm(tmppath, contract_data, rpc, rpc2, checkresult, mocker):  # type: ignore # noqa
    plan = contract_data.plan
    runner = CliRunner()

    for _ in range(5 + plan.num_blocks_in_period):
        rpc.generate_block()

    sync_rpc(rpc, rpc2)

    tx_data_file_str = str(tmppath / "tx_mutual_data")
    plan_file_str = str(tmppath / "plan")
    creditor_data_str = str(tmppath / "creditor")
    args = [
        "createmutual",
        "-r",
        rpc.service_url,
        "-p",
        plan_file_str,
        "-d",
        creditor_data_str,
        "--debt",
        plan.principal_amount // 2,
        "-o",
        tx_data_file_str,
    ]
    with SafeDerivation():
        result = runner.invoke(creditor, args)
        checkresult(result)
    mutual_tx_file_str = str(tmppath / "tx_mutual_signed_partially")
    debtor_data_str = str(tmppath / "debtor")
    args = [
        "updatemutual",
        "-r",
        rpc.service_url,
        "-p",
        plan_file_str,
        "-d",
        debtor_data_str,
        "--tx",
        tx_data_file_str,
        "-o",
        mutual_tx_file_str,
    ]
    with SafeDerivation():
        result = runner.invoke(debtor, args, input="yes")
        checkresult(result)
    args = [
        "signmutual",
        "-r",
        rpc.service_url,
        "--debt",
        plan.principal_amount // 2,
        "--tx",
        mutual_tx_file_str,
    ]
    mocker.patch("cli_common.wait_confirm", wait_confirm)
    with SafeDerivation():
        result = runner.invoke(creditor, args, input="yes")
        checkresult(result)
