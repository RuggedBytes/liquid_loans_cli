# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from click.testing import CliRunner

from debtor_cli import debtor

from lib.utils import SafeDerivation

from . import wait_confirm


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


def test_debtpay_partial_confirm(tmppath, rpc, contract_data, checkresult, mocker):  # type: ignore # noqa
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
        result = runner.invoke(debtor, args, input="yes\nno")
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


def test_debtpay_full_confirm(tmppath, rpc, contract_data, checkresult, mocker):  # type: ignore # noqa
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
        result = runner.invoke(debtor, args, input="yes\nno")
        checkresult(result)
