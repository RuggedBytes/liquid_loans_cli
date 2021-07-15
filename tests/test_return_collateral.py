# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from click.testing import CliRunner

from creditor_cli import creditor
from debtor_cli import debtor

from lib.utils import SafeDerivation

from . import wait_confirm, sync_rpc


def test_return_collataral(tmppath, rpc, rpc2, contract_data, checkresult, mocker):  # type: ignore # noqa
    runner = CliRunner()
    mocker.patch("cli_common.wait_confirm", wait_confirm)
    plan = contract_data.plan
    for _ in range(5):
        rpc.generate_block()

    sync_rpc(rpc, rpc2)

    # Make one partial payment
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
    with SafeDerivation():
        result = runner.invoke(debtor, args)
        checkresult(result)

    # take this payment
    creditor_data_str = str(tmppath / "creditor")
    args = [
        "getpayment",
        "-r",
        rpc.service_url,
        "-p",
        plan_file_str,
        "-d",
        creditor_data_str,
        "--force",
    ]
    with SafeDerivation():
        result = runner.invoke(creditor, args)
        checkresult(result)

    for _ in range(plan.num_blocks_in_period * 2):
        rpc.generate_block()

    sync_rpc(rpc, rpc2)

    # the first revoking
    args = [
        "revokewindow",
        "-r",
        rpc.service_url,
        "-p",
        plan_file_str,
        "-d",
        creditor_data_str,
        "--force",
    ]
    with SafeDerivation():
        result = runner.invoke(creditor, args)
        checkresult(result)

    for _ in range(plan.num_blocks_in_period):
        rpc.generate_block()

    sync_rpc(rpc, rpc2)

    # the second revoking
    with SafeDerivation():
        result = runner.invoke(creditor, args)
        checkresult(result)

    for _ in range(plan.num_blocks_in_period):
        rpc.generate_block()

    sync_rpc(rpc, rpc2)

    # grab collateral
    with SafeDerivation():
        result = runner.invoke(creditor, args)
        checkresult(result)

    args = [
        "getcollaterall",
        "-r",
        rpc.service_url,
        "-p",
        plan_file_str,
        "-d",
        debtor_data_str,
        "--force",
    ]
    with SafeDerivation():
        result = runner.invoke(debtor, args)
        checkresult(result)


def test_return_collataral_confirm(  # type: ignore
    tmppath, rpc, rpc2, contract_data, checkresult, mocker
):
    runner = CliRunner()
    mocker.patch("cli_common.wait_confirm", wait_confirm)
    plan = contract_data.plan
    for _ in range(5):
        rpc.generate_block()

    sync_rpc(rpc, rpc2)

    # Make one partial payment
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
    with SafeDerivation():
        result = runner.invoke(debtor, args)
        checkresult(result)

    # take this payment
    creditor_data_str = str(tmppath / "creditor")
    args = [
        "getpayment",
        "-r",
        rpc.service_url,
        "-p",
        plan_file_str,
        "-d",
        creditor_data_str,
        "--force",
    ]
    with SafeDerivation():
        result = runner.invoke(creditor, args)
        checkresult(result)

    for _ in range(plan.num_blocks_in_period * 2):
        rpc.generate_block()

    sync_rpc(rpc, rpc2)

    # the first revoking
    args = [
        "revokewindow",
        "-r",
        rpc.service_url,
        "-p",
        plan_file_str,
        "-d",
        creditor_data_str,
        "--force",
    ]
    with SafeDerivation():
        result = runner.invoke(creditor, args)
        checkresult(result)

    for _ in range(plan.num_blocks_in_period):
        rpc.generate_block()

    sync_rpc(rpc, rpc2)

    # the second revoking
    with SafeDerivation():
        result = runner.invoke(creditor, args)
        checkresult(result)

    for _ in range(plan.num_blocks_in_period):
        rpc.generate_block()

    sync_rpc(rpc, rpc2)

    # grab collateral
    with SafeDerivation():
        result = runner.invoke(creditor, args)
        checkresult(result)

    args = [
        "getcollaterall",
        "-r",
        rpc.service_url,
        "-p",
        plan_file_str,
        "-d",
        debtor_data_str,
    ]
    mocker.patch("cli_common.wait_confirm", wait_confirm)
    with SafeDerivation():
        result = runner.invoke(debtor, args, input="yes")
        checkresult(result)
