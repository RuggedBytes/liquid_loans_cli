# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from click.testing import CliRunner

from creditor_cli import creditor
from debtor_cli import debtor

from lib.utils import SafeDerivation

from . import wait_confirm, sync_rpc


def test_get_payment_partial(tmppath, rpc, rpc2, contract_data, checkresult, mocker):  # type: ignore # noqa
    mocker.patch("cli_common.wait_confirm", wait_confirm)
    runner = CliRunner()
    for _ in range(5):
        rpc.generate_block()

    sync_rpc(rpc, rpc2)

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

    rpc.generate_block()
    sync_rpc(rpc, rpc2)

    # try to get the payment
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


def test_get_payment_full(tmppath, rpc, rpc2, contract_data, checkresult, mocker):  # type: ignore # noqa
    mocker.patch("cli_common.wait_confirm", wait_confirm)
    runner = CliRunner()
    for _ in range(5):
        rpc.generate_block()

    sync_rpc(rpc, rpc2)

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
    with SafeDerivation():
        result = runner.invoke(debtor, args)
        checkresult(result)

    rpc.generate_block()
    sync_rpc(rpc, rpc2)

    # try to get the payment
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


def test_get_payment_partial_confirm(  # type: ignore
    tmppath, rpc, rpc2, contract_data, checkresult, mocker
):
    mocker.patch("cli_common.wait_confirm", wait_confirm)

    runner = CliRunner()
    for _ in range(5):
        rpc.generate_block()

    sync_rpc(rpc, rpc2)

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

    rpc.generate_block()
    sync_rpc(rpc, rpc2)

    # try to get the payment
    creditor_data_str = str(tmppath / "creditor")
    args = [
        "getpayment",
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


def test_get_payment_full_confirm(  # type: ignore
    tmppath, rpc, rpc2, contract_data, checkresult, mocker
):
    mocker.patch("cli_common.wait_confirm", wait_confirm)

    runner = CliRunner()
    for _ in range(5):
        rpc.generate_block()

    sync_rpc(rpc, rpc2)

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
    with SafeDerivation():
        result = runner.invoke(debtor, args)
        checkresult(result)

    rpc.generate_block()
    sync_rpc(rpc, rpc2)

    # try to get the payment
    creditor_data_str = str(tmppath / "creditor")
    args = [
        "getpayment",
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
