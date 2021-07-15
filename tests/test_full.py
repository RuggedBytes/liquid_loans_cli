# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import json
import os
import time
from decimal import Decimal
from random import randrange, randint

import elementstx  # noqa: F401
from bitcointx import select_chain_params
from bitcointx.core import b2x, lx, satoshi_to_coins, x, Hash160
from bitcointx.core.key import CKey
from bitcointx.core.script import (
    SIGHASH_ALL, SIGHASH_ANYONECANPAY, standard_keyhash_scriptpubkey,
    SIGVERSION_WITNESS_V0, CScript, CScriptWitness, SIGHASH_Type
)
from bitcointx.rpc import JSONRPCError
from bitcointx.wallet import P2WPKHCoinAddress
from click.testing import CliRunner
from elementstx.core import (
    CAsset, CConfidentialValue, CElementsMutableTxInWitness,
    CElementsTransaction, CElementsMutableTransaction
)
from elementstx.core.script import CElementsScript
from elementstx.wallet import CCoinConfidentialAddress

from cli_common import load_data_with_checking_hash, save_to_json_with_hash
from facilitator_cli import facilitator
from lib.types import PlanData, Rates
from lib.utils import SafeDerivation

from . import sync_rpc, wait_confirm


def sign_p2wpkh_input(
    tx: CElementsMutableTransaction, input_index: int,
    amountcommitment: CConfidentialValue, key: CKey,
    flags: SIGHASH_Type = SIGHASH_ALL
) -> None:
    rds = CElementsScript(standard_keyhash_scriptpubkey(Hash160(key.pub)))
    sighash = rds.sighash(tx, input_index, flags,
                          amount=amountcommitment,
                          sigversion=SIGVERSION_WITNESS_V0)

    sig = key.sign(sighash) + bytes([flags])

    tx.vin[input_index].scriptSig = CScript()
    tx.wit.vtxinwit[input_index] = CElementsMutableTxInWitness(
        CScriptWitness([CScript(sig), CScript(key.pub)]))


def test_main(tmppath, rpc, rpc2, mocker, checkresult, capsys):  # type: ignore
    runner = CliRunner()
    select_chain_params("elements")
    # ---------generate collateral----------
    example_collateral_asset_amount = randrange(100, 100000)
    issue = rpc.issueasset(
        satoshi_to_coins(example_collateral_asset_amount * 10), 0
    )
    collateral_asset = CAsset(lx(issue["asset"]))
    collateral_asset_amount = randrange(100, example_collateral_asset_amount)
    collateral_asset_key = CKey(os.urandom(32))
    collateral_asset_blinding_key = CKey(os.urandom(32))
    collateral_asset_addr = CCoinConfidentialAddress.from_unconfidential(
        P2WPKHCoinAddress.from_pubkey(collateral_asset_key.pub),
        collateral_asset_blinding_key.pub,
    )
    txid = rpc.sendtoaddress(
        str(collateral_asset_addr),
        satoshi_to_coins(collateral_asset_amount),
        "",
        "",
        False,
        False,
        1,
        "CONSERVATIVE",
        collateral_asset.to_hex(),
        False,
    )
    tx_imm = CElementsTransaction.deserialize(x(rpc.getrawtransaction(txid)))

    for txout_index, txout in enumerate(tx_imm.vout):
        if txout.scriptPubKey == collateral_asset_addr.to_scriptPubKey():
            index = txout_index
            break
    else:
        assert 0, "out not found"

    collateral_commitment = CConfidentialValue(
        tx_imm.vout[index].nValue.commitment
    )
    debtor_control_addr = rpc.getnewaddress()
    debtor_change_addr = rpc.getnewaddress()
    debtor_receive_addr = rpc.getnewaddress()
    collateral_info = dict(
        txid=txid,
        vout_index=index,
        blinding_key=b2x(collateral_asset_blinding_key.secret_bytes),
        control_addr=debtor_control_addr,
        collateral_change_addr=debtor_change_addr,
        receive_addr=debtor_receive_addr,
    )
    collateral_info_file_str = str(tmppath / "collateral_info")
    save_to_json_with_hash(collateral_info_file_str, collateral_info)

    # ---------generate principal----------
    example_principal_asset_amount = randrange(1000, 1000_000)
    issue = rpc.issueasset(
        satoshi_to_coins(example_principal_asset_amount * 10), 0
    )
    principal_asset = CAsset(lx(issue["asset"]))
    principal_asset_amount = randrange(100, example_principal_asset_amount)

    creditor_control_addr = rpc.getnewaddress()
    creditor_change_addr = rpc.getnewaddress()

    principal_asset_key = CKey(os.urandom(32))
    principal_asset_blinding_key = CKey(os.urandom(32))
    principal_asset_addr = CCoinConfidentialAddress.from_unconfidential(
        P2WPKHCoinAddress.from_pubkey(principal_asset_key.pub),
        principal_asset_blinding_key.pub,
    )
    txid = rpc.sendtoaddress(
        str(principal_asset_addr),
        satoshi_to_coins(principal_asset_amount),
        "",
        "",
        False,
        False,
        1,
        "CONSERVATIVE",
        principal_asset.to_hex(),
        False,
    )
    tx_imm = CElementsTransaction.deserialize(x(rpc.getrawtransaction(txid)))

    for txout_index, txout in enumerate(tx_imm.vout):
        if txout.scriptPubKey == principal_asset_addr.to_scriptPubKey():
            index = txout_index
            break
    else:
        assert 0, "out not found"

    principal_commitment = CConfidentialValue(
        tx_imm.vout[index].nValue.commitment)

    principal_info = dict(
        txid=txid,
        vout_index=index,
        blinding_key=b2x(principal_asset_blinding_key.secret_bytes),
        control_addr=creditor_control_addr,
        principal_change_addr=creditor_change_addr,
    )
    principal_info_file_str = str(tmppath / "principal_info")
    save_to_json_with_hash(principal_info_file_str, principal_info)

    # ------generate plan data------
    rate_due = Decimal(2)
    rate_early = Decimal("0.1")
    rate_collateral_penalty = Decimal(10)
    rates_late = [Decimal(5.0), Decimal(7.5)]
    M = len(rates_late)+1
    N = randrange(3, 8)
    S = randint(max(N, M)+1, N+M)
    collateral_amount = randrange(10, collateral_asset_amount)
    plan = PlanData(
        principal_asset=principal_asset,
        principal_amount=randrange(10, principal_asset_amount),
        collateral_asset=collateral_asset,
        collateral_amount=collateral_amount,
        N=N, S=S,
        rates=Rates(rate_due=rate_due, rate_early=rate_early,
                    rate_collateral_penalty=rate_collateral_penalty,
                    rates_late=rates_late),
        num_blocks_in_period=randrange(3, 8),
        amount_C_uncond=max(1, collateral_amount//3)
    )
    plan_file_str = str(tmppath / "plan")
    with open(plan_file_str, mode="w") as f:
        f.write(plan.to_json())

    # Generate one block
    rpc.generate_block()
    # Wait confirm
    for _ in range(20):
        try:
            rpc2.getrawtransaction(principal_info["txid"], 1)
        except JSONRPCError as e:
            if e.error["code"] == -5:
                time.sleep(1)
                rpc.generate_block()
                continue
        break
    else:
        raise TimeoutError

    sync_rpc(rpc, rpc2)

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
        1
    ]

    mocker.patch("lib.rpc_utils.wait_confirm", wait_confirm)

    with SafeDerivation():
        result = runner.invoke(facilitator, args)
        checkresult(result)
    rpc2.generate_block()
    sync_rpc(rpc, rpc2)

    creditor_tx_file = str(tmppath / "creditor")
    tx_dict = load_data_with_checking_hash(creditor_tx_file)
    tx_mut = CElementsMutableTransaction.deserialize(x(tx_dict["tx"]))
    sign_p2wpkh_input(
        tx_mut,
        1,
        principal_commitment,
        principal_asset_key,
        flags=SIGHASH_ALL | SIGHASH_ANYONECANPAY,
    )
    sign_data = {
        "signscript": b2x(tx_mut.vin[1].scriptSig),
        "witnessscript": b2x(tx_mut.wit.vtxinwit[1].serialize()),
    }
    creditor_witness_str = str(tmppath / "creditor_witness")
    with open(creditor_witness_str, mode="w") as f:
        f.write(json.dumps(sign_data, indent=4))

    debtor_tx_file = str(tmppath / "debtor")
    tx_dict = load_data_with_checking_hash(debtor_tx_file)
    tx_mut = CElementsMutableTransaction.deserialize(x(tx_dict["tx"]))
    sign_p2wpkh_input(
        tx_mut,
        0,
        collateral_commitment,
        collateral_asset_key,
        flags=SIGHASH_ALL | SIGHASH_ANYONECANPAY,
    )

    sign_data = {
        "signscript": b2x(tx_mut.vin[0].scriptSig),
        "witnessscript": b2x(tx_mut.wit.vtxinwit[0].serialize()),
    }
    debtor_witness_str = str(tmppath / "debtor_witness")
    with open(debtor_witness_str, mode="w") as f:
        f.write(json.dumps(sign_data, indent=4))

    loan_tx_str = str(tmppath / "loan_tx")
    args = [
        "sign",
        "-r",
        rpc2.service_url,
        "-t",
        loan_tx_str,
        "-c",
        creditor_witness_str,
        "-d",
        debtor_witness_str,
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
    rpc2.generate_block()
    sync_rpc(rpc, rpc2)

    txid = rpc2.sendrawtransaction(tx_str)
    with capsys.disabled():
        print(f"contract tx was sent {txid}")
