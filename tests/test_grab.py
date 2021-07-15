# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from click.testing import CliRunner

from creditor_cli import creditor

from lib.utils import SafeDerivation

from . import wait_confirm, sync_rpc


def test_grab_collateral(tmppath, rpc, rpc2, contract_data, checkresult, mocker):  # type: ignore # noqa

    plan = contract_data.plan
    creditor_data_str = str(tmppath / "creditor")
    runner = CliRunner()
    mocker.patch("cli_common.wait_confirm", wait_confirm)

    plan_file_str = str(tmppath / "plan")
    for _ in range(5 + plan.num_blocks_in_period):
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


def test_grab_collateral_confirm(  # type: ignore
    tmppath, rpc, rpc2, contract_data, checkresult, mocker
):
    mocker.patch("cli_common.wait_confirm", wait_confirm)
    plan = contract_data.plan
    creditor_data_str = str(tmppath / "creditor")
    runner = CliRunner()

    plan_file_str = str(tmppath / "plan")
    for _ in range(5 + plan.num_blocks_in_period):
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
    ]
    with SafeDerivation():
        result = runner.invoke(creditor, args, input="yes")
        checkresult(result)

    for _ in range(plan.num_blocks_in_period):
        rpc.generate_block()

    sync_rpc(rpc, rpc2)

    # the second revoking
    with SafeDerivation():
        result = runner.invoke(creditor, args, input="yes")
        checkresult(result)

    for _ in range(plan.num_blocks_in_period):
        rpc.generate_block()

    sync_rpc(rpc, rpc2)

    # grab collateral
    with SafeDerivation():
        result = runner.invoke(creditor, args, input="yes")
        checkresult(result)
