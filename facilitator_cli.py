#!/usr/bin/env python3

# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import json
import os

import click
import elementstx  # noqa: F401
from bitcointx import select_chain_params
from bitcointx.core import (
    CMutableTransaction,
    CTransaction,
    CMutableTxIn,
    CMutableTxInWitness,
    b2lx,
    b2x,
    x,
)
from bitcointx.core.script import CScript
from bitcointx.core.key import CKey
from bitcointx.rpc import JSONRPCError
from bitcointx.wallet import CCoinExtKey

from elementstx.wallet import CCoinConfidentialAddress

from cli_common import (
    load_data_with_checking_hash, save_to_json_with_hash, read_plandata,
    network_option
)
from lib.constants import (
    CONTRACT_COLLATERAL_INP_INDEX,
    CONTRACT_PRINCIPAL_INP_INDEX
)
from lib.loan_utils import create_loan_transaction
from lib.rpc_utils import calculate_fee, get_fee_utxo, get_bitcoin_asset
from lib.types import (
    CreditorLoanStartInfo,
    DebtorLoanStartInfo,
    RPCPathParamType,
    ElementsRPCCaller
)

CONTRACT_FEE_INP_INDEX = 2


@click.group()
def facilitator() -> None:
    ...


@facilitator.command()
@click.option(
    "-r",
    "--rpc",
    type=RPCPathParamType(),
    help="config dir path",
    required=True,
)
@click.option(
    "-p",
    "--plan",
    type=click.Path(
        exists=True,
        dir_okay=False,
        resolve_path=True,
    ),
    help="path to plan data",
)
@click.option(
    "-l",
    "--loan",
    type=click.Path(
        exists=True,
        dir_okay=False,
        resolve_path=True,
    ),
    required=True,
    help="path to principal info",
)
@click.option(
    "-c",
    "--collateral",
    type=click.Path(
        exists=True,
        dir_okay=False,
        resolve_path=True,
    ),
    required=True,
    help="path to collateral info",
)
@click.option(
    "-oc",
    "--output-creditor",
    type=click.Path(
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
        allow_dash=False,
    ),
    required=True,
    help="path to creditor info",
)
@click.option(
    "-od",
    "--output-debtor",
    type=click.Path(
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
        allow_dash=False,
    ),
    required=True,
    help="path to debtor info",
)
@click.option(
    "-ot",
    "--output-tx",
    type=click.Path(
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
        allow_dash=True,
    ),
    required=True,
    default="-",
    help="path to tx data",
)
@click.option(
    "--min-output",
    "min_output",
    type=int,
    default=1,
    help="path to write transaction data",
)
@click.option(
    "--contract-start-delay",
    "contract_start_delay",
    type=int,
    required=True,
    help="Delay in blocks to the start of the contract from the current block",
)
@network_option
def make(
    rpc: ElementsRPCCaller,
    plan: str,
    loan: str,
    collateral: str,
    output_creditor: str,
    output_debtor: str,
    output_tx: str,
    min_output: int,
    contract_start_delay: int,
    network: str
) -> None:
    select_chain_params(network)

    if contract_start_delay < 0:
        raise click.UsageError(f"contract_start_delay must be positive")

    repayment_plan = read_plandata(plan).to_repayment_plan(min_output)

    debtor_start_data = load_data_with_checking_hash(collateral)
    try:
        txstr = rpc.getrawtransaction(debtor_start_data["txid"])
    except JSONRPCError as e:
        raise click.UsageError(
            f"Can't get transaction {debtor_start_data['txid']}"
            f" expected to contain the principal: {e}"
        )

    tx = CTransaction.deserialize(x(txstr))

    assert isinstance(debtor_start_data["vout_index"], int)

    debtor_start_info = DebtorLoanStartInfo(
        tx=tx, vout_index=int(debtor_start_data["vout_index"]),
        blinding_key=CKey(x(debtor_start_data["blinding_key"])),
        control_addr=CCoinConfidentialAddress(
            debtor_start_data["control_addr"]),
        receive_addr=CCoinConfidentialAddress(
            debtor_start_data["receive_addr"]),
        collateral_change_addr=CCoinConfidentialAddress(
            debtor_start_data["collateral_change_addr"]),
        plan=repayment_plan
    )

    creditor_start_data = load_data_with_checking_hash(loan)
    try:
        txstr = rpc.getrawtransaction(creditor_start_data["txid"])
    except JSONRPCError as e:
        raise click.UsageError(
            f"Can't get transaction {creditor_start_data['txid']}"
            f" expected to contain collateral: {e}"
        )
    tx = CTransaction.deserialize(x(txstr))

    creditor_start_info = CreditorLoanStartInfo(
        tx=tx, vout_index=int(creditor_start_data["vout_index"]),
        blinding_key=CKey(x(creditor_start_data["blinding_key"])),
        control_addr=CCoinConfidentialAddress(
            creditor_start_data["control_addr"]),
        principal_change_addr=CCoinConfidentialAddress(
            creditor_start_data["principal_change_addr"]),
        plan=repayment_plan
    )

    fee_amount = calculate_fee(rpc)

    print(f"Calculated fee amount for the transaction: {fee_amount}")

    bitcoin_asset = get_bitcoin_asset(rpc)
    fee_utxo_info = get_fee_utxo(rpc, fee_amount, bitcoin_asset)
    fee_cout = fee_utxo_info.outpoint

    # Lock this utxo
    rpc.lockunspent(False, [{"txid": b2lx(fee_cout.hash), "vout": fee_cout.n}])

    shared_blinding_xkey = CCoinExtKey.from_seed(os.urandom(32))
    start_block_num = rpc.getblockcount() + contract_start_delay

    fee_change_addr = CCoinConfidentialAddress(rpc.getnewaddress())

    tx, creditor_ctl_asset, debtor_ctl_asset = create_loan_transaction(
        repayment_plan,
        creditor_start_info,
        debtor_start_info,
        shared_blinding_xkey,
        fee_utxo_info,
        fee_change_addr,
        bitcoin_asset,
        start_block_num=start_block_num,
        fee_amount=fee_amount,
    )

    tx_for_alice = tx.clone()
    tx_for_alice.vin[CONTRACT_COLLATERAL_INP_INDEX] = CMutableTxIn()
    creditor_info = {
        "tx": b2x(tx_for_alice.to_immutable().serialize()),
        "shared-blinding-xkey": str(shared_blinding_xkey),
        "debtor-control-asset": debtor_ctl_asset.to_hex(),
        "bitcoin-asset": bitcoin_asset.to_hex(),
        "start-block-num": start_block_num,
    }

    save_to_json_with_hash(output_creditor, creditor_info)

    # mask Alice's input when sending to Bob
    tx_for_bob = tx.clone()
    tx_for_bob.vin[CONTRACT_PRINCIPAL_INP_INDEX] = CMutableTxIn()
    debtor_info = {
        "tx": b2x(tx_for_bob.to_immutable().serialize()),
        "shared-blinding-xkey": str(shared_blinding_xkey),
        "creditor-control-asset": creditor_ctl_asset.to_hex(),
        "bitcoin-asset": bitcoin_asset.to_hex(),
        "start-block-num": start_block_num,
    }

    save_to_json_with_hash(output_debtor, debtor_info)

    with click.open_file(output_tx, mode="x") as f:
        f.write(b2x(tx.to_immutable().serialize()))

    print(f"Contract transaction was saved to {output_tx}")
    print(f"The transaction can not be broadcast until block "
          f"{start_block_num}")


@facilitator.command()
@click.option(
    "-r",
    "--rpc",
    type=RPCPathParamType(),
    help="config dir path",
    required=True,
)
@click.option(
    "-t",
    "--tx",
    type=click.Path(
        exists=True,
        dir_okay=False,
        resolve_path=True,
    ),
    help="path to loan transaction",
)
@click.option(
    "-c",
    "--creditor-witness",
    type=click.Path(
        exists=True,
        dir_okay=False,
        resolve_path=True,
    ),
    required=True,
    help="path to creditor witness",
)
@click.option(
    "-d",
    "--debtor-witness",
    type=click.Path(
        exists=True,
        dir_okay=False,
        resolve_path=True,
    ),
    required=True,
    help="path to debtor witness",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(
        dir_okay=False,
        resolve_path=True,
        allow_dash=True,
    ),
    default="-",
    help="path to output transaction",
)
@network_option
def sign(rpc: ElementsRPCCaller, tx: str,
         creditor_witness: str, debtor_witness: str, output: str,
         network: str) -> None:
    select_chain_params(network)
    with click.open_file(tx) as f:
        loan_tx = CMutableTransaction.deserialize(x(f.read()))
    with click.open_file(creditor_witness) as f:
        data_alice = json.loads(f.read())
    with click.open_file(debtor_witness) as f:
        data_bob = json.loads(f.read())

    w_sign_bob = CMutableTxInWitness.deserialize(
        x(data_bob["witnessscript"]))
    w_sign_alice = CMutableTxInWitness.deserialize(
        x(data_alice["witnessscript"]))
    s_sign_bob = CScript(x(data_bob["signscript"]))
    s_sign_alice = CScript(x(data_alice["signscript"]))
    loan_tx.wit.vtxinwit[CONTRACT_COLLATERAL_INP_INDEX] = w_sign_bob
    loan_tx.wit.vtxinwit[CONTRACT_PRINCIPAL_INP_INDEX] = w_sign_alice
    loan_tx.vin[CONTRACT_COLLATERAL_INP_INDEX].scriptSig = s_sign_bob
    loan_tx.vin[CONTRACT_PRINCIPAL_INP_INDEX].scriptSig = s_sign_alice
    result = rpc.signrawtransactionwithwallet(b2x(loan_tx.serialize()))
    if not result["complete"]:
        raise click.UsageError(
            f"Can't sign the transaction: {result['errors']}"
        )
    with click.open_file(output, mode="x") as f:
        f.write(result["hex"])
    # Unlock fee the utxo what was locked in previous step
    rpc.lockunspent(
        True,
        [
            {
                "txid": b2lx(loan_tx.vin[CONTRACT_FEE_INP_INDEX].prevout.hash),
                "vout": loan_tx.vin[CONTRACT_FEE_INP_INDEX].prevout.n,
            }
        ],
    )

    print(f"Signed contract transaction was saved to {output}")
    print(f"UTXO {b2lx(loan_tx.vin[CONTRACT_FEE_INP_INDEX].prevout.hash)}:"
          f"{loan_tx.vin[CONTRACT_FEE_INP_INDEX].prevout.n} was locked")


if __name__ == "__main__":
    facilitator()
