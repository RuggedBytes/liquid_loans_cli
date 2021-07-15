# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from click.testing import CliRunner

from creditor_cli import creditor
from debtor_cli import debtor
from facilitator_cli import facilitator

from lib.utils import SafeDerivation

from . import sync_rpc, wait_confirm


def test_participants_sign(  # type: ignore
    tmppath, rpc, rpc2, participants_data, checkresult, capsys, mocker
):
    runner = CliRunner()
    principal_info_file_str = str(tmppath / "principal_info")
    collateral_info_file_str = str(tmppath / "collateral_info")
    plan_file_str = str(tmppath / "plan")
    args = [
        "make",
        "-r",
        rpc2.service_url,
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
        3
    ]

    mocker.patch("lib.rpc_utils.wait_confirm", wait_confirm)

    with SafeDerivation():
        result = runner.invoke(facilitator, args)
        checkresult(result)

    rpc.generate_block()
    sync_rpc(rpc, rpc2)
    rpc2.generate_block()
    sync_rpc(rpc, rpc2)

    creditor_data_str = str(tmppath / "creditor")
    creditor_witness_path_str = str(tmppath / "creditor_witness")
    args = [
        "sign",
        "-r",
        rpc.service_url,
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
        rpc.service_url,
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
        rpc2.service_url,
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

    rpc.generate_block()
    sync_rpc(rpc, rpc2)
    rpc.generate_block()
    sync_rpc(rpc, rpc2)

    txid = rpc.sendrawtransaction(tx_str)
    with capsys.disabled():
        print(f"contract transaction was sent txid = {txid}")


def test_biggest_dust(  # type: ignore
    tmppath, rpc, rpc2, participants_data, checkresult, capsys, mocker
):
    runner = CliRunner()
    principal_info_file_str = str(tmppath / "principal_info")
    collateral_info_file_str = str(tmppath / "collateral_info")
    creditor_data_str = str(tmppath / "creditor")
    plan_file_str = str(tmppath / "plan")
    args = [
        "make",
        "-r",
        rpc2.service_url,
        "-p",
        plan_file_str,
        "-l",
        principal_info_file_str,
        "-c",
        collateral_info_file_str,
        "--output-creditor",
        creditor_data_str,
        "--output-debtor",
        str(tmppath / "debtor"),
        "--output-tx",
        str(tmppath / "loan_tx"),
        "--contract-start-delay",
        1
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
    creditor_witness_path_str = str(tmppath / "creditor_witness")
    args = [
        "sign",
        "-r",
        rpc.service_url,
        "-p",
        plan_file_str,
        "-d",
        creditor_data_str,
        "-o",
        creditor_witness_path_str,
        "--min-output",
        10000000,
    ]
    with SafeDerivation():
        result = runner.invoke(creditor, args)

    assert result.exit_code
    assert result.exc_info is not None
