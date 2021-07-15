# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from click.testing import CliRunner

from creditor_cli import creditor

from lib.utils import SafeDerivation

from . import wait_confirm, sync_rpc


def test_revoke_window(tmppath, rpc, rpc2, contract_data, checkresult, mocker):  # type: ignore # noqa
    runner = CliRunner()
    mocker.patch("cli_common.wait_confirm", wait_confirm)
    plan = contract_data.plan
    plan_file_str = str(tmppath / "plan")
    creditor_data_str = str(tmppath / "creditor")

    for _ in range(5 + plan.num_blocks_in_period):
        rpc.generate_block()

    sync_rpc(rpc, rpc2)

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
