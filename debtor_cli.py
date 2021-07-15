#!/usr/bin/env python3

# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# pylama:ignore=C901

import hashlib
import json
from decimal import Decimal
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any

import click
from bitcointx import select_chain_params
from bitcointx.core import (
    Uint256,
    CTransaction,
    b2lx,
    b2x,
    lx,
    x,
)
from bitcointx.core.key import CPubKey
from bitcointx.core.script import CScript, MAX_SCRIPT_ELEMENT_SIZE
from bitcointx.wallet import CCoinAddress, CCoinExtKey, P2WSHCoinAddress

from elementstx.core import (
    BlindingInputDescriptor,
    CAsset,
    CConfidentialAsset,
    CConfidentialValue,
    calculate_asset,
    generate_asset_entropy,
    CElementsTransaction,
    CElementsMutableTransaction,
    CElementsMutableTxIn,
    CElementsMutableTxWitness,
    CElementsMutableTxInWitness,
    CElementsTxOut,
    CElementsMutableTxOut,
    CElementsMutableTxOutWitness,
    CElementsOutPoint,
)
from elementstx.wallet import CCoinConfidentialAddress

from cli_common import (
    asset_amount_is_enough,
    data_option,
    force_option,
    min_output_option,
    plan_option,
    print_psbt,
    read_aux_data,
    read_plandata,
    rpc_option,
    network_option,
    save_to_json_with_hash,
    send_tx_with_confirm,
)
from lib import (
    check_issuance_amount_1_no_reissuance,
    check_output,
)
from lib.constants import (
    BLIND_PUB_COLLATERAL_GRAB_TX_PATH,
    COMMON_TX_APPROX_SIZE,
    CONTRACT_COLLATERAL_INP_INDEX,
    CONTRACT_COLLATERAL_OUT_INDEX,
    CONTRACT_PRINCIPAL_INP_INDEX,
    CONTRACT_DEBTOR_CONTROL_OUT_INDEX,
    CONTRACT_PRINCIPAL_OUT_INDEX,
    DEBT_RETURN_TX_APPROX_SIZE,
    LOCKED_COLLATERAL_PATH,
    MIN_GUARANTEED_CHANGE,
    MIN_NUM_CONTRACT_INPUT,
    MIN_NUM_CONTRACT_OUTPUT,
)
from lib.loan_utils import spend_via_control_asset_tx
from lib.loan_utils import return_debt_tx
from lib.rpc_utils import (
    calculate_fee,
    find_asset_utxo_by_amount,
    find_asset_utxo_by_min_amount,
    find_blinded_asset_utxo_by_min_amount,
    get_blinding_key_for_script,
    get_fee_utxo,
    get_utxo_by_outpoint,
    is_scriptpubkey_mine,
    make_utxo,
    parse_utxo_dict,
    sign_tx_with_wallet,
    track_contract_txs,
    get_bitcoin_asset
)
from lib.types import (
    ElementsRPCCaller,
    Amount,
    AmountParamType,
    AssetParamType,
    BlindingInfo,
    PlanData,
    RepaymentPlan,
    CheckOutputError,
    Rates,
    CreditorAsset,
    DebtorAsset,
    BitcoinAsset,
    RateListOption,
    DataLookupError,
    ContractTransaction,
    VerticalProgressionStage
)
from lib.utils import (
    find_explicit_asset_txout_index, safe_derive, SafeDerivation,
    blind_tx_and_validate
)
from lib.validators import (
    ValidationFailure,
    validate_num_blocks_in_period,
    validate_rate,
    validate_total_periods,
    validate_total_steps,
)
from lib.generator import generate_abl_contract_for_lateral_stage
from lib.sign import sign_for_covenant
from lib.scripts import get_control_script


def compute_info(
     rpc: ElementsRPCCaller,
     debtor_data: Dict[str, Any],
     plandata: PlanData,
     min_output: int,
     cache_dir: Optional[Path] = None,
) -> Tuple[RepaymentPlan,
           List[ContractTransaction], List[VerticalProgressionStage],
           CreditorAsset, DebtorAsset, BitcoinAsset]:
    shared_blinding_xkey = CCoinExtKey(debtor_data["shared-blinding-xkey"])
    current_block = rpc.getblockchaininfo()["blocks"]
    first_contract_tx = CElementsMutableTransaction.deserialize(
        x(debtor_data["tx"]))

    repayment_plan = plandata.to_repayment_plan(min_output)

    contract_hash_preimage = shared_blinding_xkey.pub + str(
        repayment_plan.deterministic_representation()
    ).encode("utf-8")
    contract_hash = Uint256(hashlib.sha256(contract_hash_preimage).digest())
    debtor_control_asset = calculate_asset(
        generate_asset_entropy(
            first_contract_tx.vin[CONTRACT_COLLATERAL_INP_INDEX].prevout,
            contract_hash
        )
    )
    unblind_result = first_contract_tx.vout[
        CONTRACT_COLLATERAL_OUT_INDEX
    ].unblind_confidential_pair(
        safe_derive(shared_blinding_xkey, LOCKED_COLLATERAL_PATH).priv,
        first_contract_tx.wit.vtxoutwit[
            CONTRACT_COLLATERAL_OUT_INDEX
        ].rangeproof,
    )
    if unblind_result.error:
        raise click.ClickException(
            f"cannot unblind locked collateral output: {unblind_result.error}"
        )

    creditor_control_asset = CAsset(lx(debtor_data["creditor-control-asset"]))

    bitcoin_asset = get_bitcoin_asset(rpc)

    with SafeDerivation():
        generate_abl_contract_for_lateral_stage(
            repayment_plan.first_lateral_stage,
            shared_blinding_xkey,
            debtor_data["start-block-num"],
            creditor_control_asset,
            debtor_control_asset,
            bitcoin_asset,
            unblind_result.get_descriptor(),
        )

    contract_tx_list, vstage_list = track_contract_txs(
        b2lx(
            first_contract_tx.vin[CONTRACT_COLLATERAL_INP_INDEX].prevout.hash
        ),
        prev_txout_index=first_contract_tx.vin[
            CONTRACT_COLLATERAL_INP_INDEX
        ].prevout.n,
        from_block=debtor_data["start-block-num"],
        to_block=current_block,
        rpc=rpc, plan=repayment_plan
    )

    cmp_tx = contract_tx_list[0].to_mutable()
    cmp_tx.wit = CElementsMutableTxWitness()

    for vin in cmp_tx.vin:
        vin.scriptSig = CScript()

    first_contract_tx.wit = CElementsMutableTxWitness()
    first_contract_tx.vin[CONTRACT_PRINCIPAL_INP_INDEX] = \
        cmp_tx.vin[CONTRACT_PRINCIPAL_INP_INDEX]

    if cmp_tx.serialize() != first_contract_tx.serialize():
        raise click.ClickException(
            f"transaction {b2lx(contract_tx_list[0].GetTxid())} found "
            f"in blockchain does not correspond to the transaction stored "
            f"in debtor's data"
        )

    return (
        repayment_plan,
        contract_tx_list,
        vstage_list,
        creditor_control_asset,
        debtor_control_asset,
        bitcoin_asset,
    )


@click.group()
def debtor() -> None:
    ...


@debtor.command()
@rpc_option
@plan_option
@data_option
@click.option(
    "--tx",
    "tx_data",
    type=click.Path(
        exists=True,
        dir_okay=False,
        resolve_path=True,
    ),
    help="path to mutual tx data",
    required=True,
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
    help="path to write creditor transaction",
)
@min_output_option
@force_option
@network_option
def updatemutual(rpc: ElementsRPCCaller, plan: str, data: str, tx_data: str,
                 output: str, min_output: int, force: bool, network: str
                 ) -> None:
    """Update mutual-spend transaction with debtor's signature
    and required witness for the collateral input"""
    select_chain_params(network)
    debtor_data = read_aux_data(data)
    with click.open_file(tx_data) as f:
        mutual_tx_data = json.loads(f.read())
    mutual_tx = CElementsMutableTransaction.deserialize(
        x(mutual_tx_data["hex"]))

    (
        repayment_plan,
        contract_tx_list,
        vstage_list,
        creditor_control_asset,
        debtor_control_asset,
        bitcoin_asset,
    ) = compute_info(rpc, debtor_data, read_plandata(plan), min_output,
                     Path(plan).parent)

    if len(contract_tx_list) != len(vstage_list) is None:
        raise click.ClickException(
            "Contract seems to be finished, cannot update mutual-spend "
            "transaction")

    vstage = vstage_list[-1]

    blind_info = BlindingInfo(
        [
            vstage.blinding_data.contract_input_descriptor,
            BlindingInputDescriptor(
                asset=creditor_control_asset,
                amount=1,
                blinding_factor=Uint256(),
                asset_blinding_factor=Uint256(),
            ),
        ],
        [CPubKey(x(data)) for data in mutual_tx_data["pubkeys"]]
    )

    last_debtor_utxo = find_asset_utxo_by_min_amount(
        rpc, debtor_control_asset, 0
    )

    if last_debtor_utxo is None:
        raise click.ClickException("The debtor control asset is not found")

    debtor_control_tx = CElementsTransaction.deserialize(
        x(rpc.getrawtransaction(last_debtor_utxo["txid"]))
    )

    debtor_control_txout_index = find_explicit_asset_txout_index(
        debtor_control_tx, debtor_control_asset
    )
    mutual_tx.vin.append(
        CElementsMutableTxIn(
            CElementsOutPoint(
                hash=debtor_control_tx.GetTxid(),
                n=debtor_control_txout_index,
            )
        )
    )
    mutual_tx.wit.vtxinwit.append(CElementsMutableTxInWitness())

    blind_info.descriptors.append(
        BlindingInputDescriptor(
            asset=debtor_control_asset,
            amount=1,
            blinding_factor=Uint256(),
            asset_blinding_factor=Uint256(),
        )
    )

    try:
        principal_txout = find_explicit_asset_txout_index(
            mutual_tx, repayment_plan.principal.asset
        )
    except DataLookupError:
        need_amount = 0
    else:
        need_amount = mutual_tx.vout[principal_txout].nValue.to_amount()

    if need_amount > 0:
        debt_utxo = find_asset_utxo_by_amount(
            rpc, vstage.plan.principal.asset, need_amount
        )
        if debt_utxo is None:
            if not force:
                answer = click.confirm(
                    f"You don't have the utxo with {need_amount} sat "
                    f"to pay the debt. Do you want it will be created?"
                )
                if not answer:
                    click.echo(
                        f"You must create an utxo with {need_amount} "
                        f"manually to add the debt to the transaction"
                    )
                    return

            debt_utxo_info = make_utxo(
                rpc, need_amount, vstage.plan.principal.asset
            )
        else:
            debt_utxo_info = parse_utxo_dict(debt_utxo)

        mutual_tx.vin.append(CElementsMutableTxIn(
            debt_utxo_info.outpoint))
        mutual_tx.wit.vtxinwit.append(CElementsMutableTxInWitness())
        blind_info.descriptors.append(
            debt_utxo_info.blinding_input_descriptor)

    debtor_collateral_return_address = CCoinConfidentialAddress(
        rpc.getnewaddress())

    mutual_tx.vout.append(
        CElementsTxOut(
            nValue=CConfidentialValue(repayment_plan.collateral.amount),
            nAsset=CConfidentialAsset(repayment_plan.collateral.asset),
            scriptPubKey=debtor_collateral_return_address.to_scriptPubKey(),
        ).to_mutable()
    )
    mutual_tx.wit.vtxoutwit.append(CElementsMutableTxOutWitness())
    blind_info.pubkeys.append(
        debtor_collateral_return_address.blinding_pubkey
    )

    fee_amount = calculate_fee(rpc, COMMON_TX_APPROX_SIZE)

    # When we add MIN_GUARANTEED_CHANGE, we will always have
    # a change output. Might be a bit wasteful if there is exact match
    # for the fee utxo, but simplifies the code, since we don't need code
    # to distinguish 'with change'/'no change' situations.
    # TODO: proper handling of the change/no_change from the fee utxo
    fee_utxo_info = get_fee_utxo(
        rpc, fee_amount + MIN_GUARANTEED_CHANGE, bitcoin_asset
    )
    fee_change_address = CCoinAddress(rpc.getnewaddress())
    fee_utxo_amount = fee_utxo_info.blinding_input_descriptor.amount
    change_amount = fee_utxo_amount - fee_amount
    assert change_amount > 0

    mutual_tx.vin.append(CElementsMutableTxIn(fee_utxo_info.outpoint))
    mutual_tx.wit.vtxinwit.append(CElementsMutableTxInWitness())
    blind_info.descriptors.append(fee_utxo_info.blinding_input_descriptor)
    mutual_tx.vout.append(
        CElementsMutableTxOut(
            nValue=CConfidentialValue(change_amount),
            nAsset=CConfidentialAsset(bitcoin_asset),
            scriptPubKey=fee_change_address.to_scriptPubKey(),
        )
    )
    mutual_tx.vout.append(
        CElementsMutableTxOut(
            nValue=CConfidentialValue(fee_amount),
            nAsset=CConfidentialAsset(bitcoin_asset),
        )
    )
    mutual_tx.wit.vtxoutwit.append(CElementsMutableTxOutWitness())
    mutual_tx.wit.vtxoutwit.append(CElementsMutableTxOutWitness())
    blind_info.pubkeys.append(CPubKey())
    blind_info.pubkeys.append(CPubKey())

    last_contract_tx = contract_tx_list[-1]

    assert sum(out.nValue.to_amount() for out in mutual_tx.vout) == sum(
        idesc.amount for idesc in blind_info.descriptors
    )
    blind_tx_and_validate(mutual_tx, blind_info.descriptors,
                          blind_info.pubkeys)

    checked_outs_data = b"".join(txout.serialize() for txout
                                 in mutual_tx.vout[:2])
    other_outs_data = b"".join(txout.serialize() for txout
                               in mutual_tx.vout[2:])

    # make sure outs data will fit into MAX_SCRIPT_ELEMENT_SIZE
    full_outs_data = b"".join(txout.serialize() for txout in mutual_tx.vout)
    assert len(full_outs_data) <= MAX_SCRIPT_ELEMENT_SIZE, len(full_outs_data)
    offset = vstage.script_data.checked_outs_hashes.index(
        hashlib.sha256(checked_outs_data).digest()
    )
    assert offset % 32 == 0
    sign_for_covenant(
        mutual_tx,
        0,
        [offset // 32, 0],
        checked_outs_data,
        other_outs_data,
        last_contract_tx.vout[CONTRACT_COLLATERAL_OUT_INDEX].nValue,
        vstage.script_data.script,
    )

    # sign debtor_control input, debt source and fee input
    mutual_tx = sign_tx_with_wallet(rpc, mutual_tx)

    with click.open_file(output, mode="x") as f:
        f.write(b2x(mutual_tx.to_immutable().serialize()))

    print(f"the transaction data was saved to {output}")


@debtor.command()
@rpc_option
@plan_option
@data_option
@min_output_option
@force_option
@network_option
def getcollaterall(rpc: ElementsRPCCaller, plan: str, data: str,
                   min_output: int, force: bool, network: str) -> None:
    """Get the collateral"""
    select_chain_params(network)
    debtor_data = read_aux_data(data)
    (
        repayment_plan,
        contract_tx_list,
        vstage_list,
        creditor_control_asset,
        debtor_control_asset,
        bitcoin_asset
    ) = compute_info(rpc, debtor_data, read_plandata(plan), min_output,
                     Path(plan).parent)

    if len(contract_tx_list) == len(vstage_list):
        raise click.ClickException("The contract is not finished yet")

    assert len(contract_tx_list) == len(vstage_list) + 1

    last_debtor_utxo = find_asset_utxo_by_min_amount(
        rpc, debtor_control_asset, 0
    )

    if last_debtor_utxo is None:
        raise click.ClickException("Can't find debtor control asset")

    debtor_control_tx = CTransaction.deserialize(
        x(rpc.getrawtransaction(last_debtor_utxo["txid"]))
    )

    debtor_control_scriptpubkey = P2WSHCoinAddress.from_redeemScript(
        get_control_script(debtor_control_asset)
    ).to_scriptPubKey()

    vstage = vstage_list[-1]
    last_contract_tx = contract_tx_list[-1]

    # XXX output at index 0 sends the part of the collateral back
    # to the debtor. This refers to the code in build_grab_transaction().
    # This is bad that this referencence is implicit, if the code
    # in build_grab_transaction() changes (if order of the outputs change),
    # this might break.
    expected_vout_n = 0
    if last_contract_tx.vout[expected_vout_n].scriptPubKey != \
            debtor_control_scriptpubkey:
        raise DataLookupError(
            f"Can`t find debtor's collateral output in the last contract "
            f"transcation {b2lx(last_contract_tx.GetTxid())}")

    unblind_result = last_contract_tx.vout[
        expected_vout_n
    ].unblind_confidential_pair(
        safe_derive(
            vstage.blinding_data.blinding_xkey,
            BLIND_PUB_COLLATERAL_GRAB_TX_PATH
        ).priv,
        last_contract_tx.wit.vtxoutwit[expected_vout_n].rangeproof,
    )

    if unblind_result.error:
        raise click.ClickException(
            f"Can't unblind locked output: {unblind_result.error}"
        )

    fee_amount = calculate_fee(rpc, COMMON_TX_APPROX_SIZE)
    fee_utxo_info = get_fee_utxo(rpc, fee_amount + MIN_GUARANTEED_CHANGE,
                                 bitcoin_asset)
    dst_addr = CCoinConfidentialAddress(rpc.getnewaddress())
    fee_change_addr = CCoinConfidentialAddress(rpc.getnewaddress())
    tx = spend_via_control_asset_tx(
        amount=unblind_result.amount,
        src_tx=last_contract_tx,
        src_txout_index=CONTRACT_COLLATERAL_OUT_INDEX,
        src_input_descriptor=unblind_result.get_descriptor(),
        control_asset=debtor_control_asset,
        control_tx=debtor_control_tx,
        fee_utxo_info=fee_utxo_info,
        fee_amount=fee_amount,
        dst_addr=dst_addr,
        fee_change_addr=fee_change_addr,
        is_final=True,
        bitcoin_asset=bitcoin_asset
    )
    if not force:
        force = click.confirm(
            f"Do you want to send the transaction"
            f" with fee {fee_amount} sat to get the collateral"
            f" (amount = {unblind_result.amount})?"
        )

    # Sign the inputs for which we have keys
    tx = sign_tx_with_wallet(rpc, tx)
    if force:
        txid = send_tx_with_confirm(rpc, tx)
        print(
            f"Successfully get the collateral amount via control asset"
            f", amount = {unblind_result.amount},"
            f" txid = {txid}"
        )
    else:
        print_psbt(rpc, tx)


@debtor.command()
@rpc_option
@plan_option
@data_option
@click.option(
    "--full",
    is_flag=True,
)
@min_output_option
@force_option
@network_option
def paydebt(rpc: ElementsRPCCaller, plan: str, data: str, full: bool,
            min_output: int, force: bool, network: str) -> None:
    """Return debt"""
    select_chain_params(network)
    debtor_data = read_aux_data(data)
    (
        repayment_plan,
        contract_tx_list,
        vstage_list,
        creditor_control_asset,
        debtor_control_asset,
        bitcoin_asset
    ) = compute_info(rpc, debtor_data, read_plandata(plan), min_output,
                     Path(plan).parent)

    if len(contract_tx_list) != len(vstage_list) is None:
        raise click.ClickException(
            "Contract seems to be finished, cannot pay the debt anymore")

    last_debtor_utxo = find_asset_utxo_by_min_amount(
        rpc, debtor_control_asset, 0
    )

    if last_debtor_utxo is None:
        raise click.ClickException("Can't find the debtor control asset")

    debtor_control_tx = CElementsTransaction.deserialize(
        x(rpc.getrawtransaction(last_debtor_utxo["txid"]))
    )

    vstage = vstage_list[-1]

    if not full:
        full = vstage.next_lateral_stage is None

    is_debt_in_btc = vstage.plan.principal.asset == bitcoin_asset
    debt_amount = (
        vstage.full_repayment_amount if full
        else vstage.regular_repayment_amount
    )
    if is_debt_in_btc:
        debt_utxo_info = None
    else:
        debt_utxo = find_asset_utxo_by_amount(
            rpc, vstage.plan.principal.asset, debt_amount
        )
        if debt_utxo is None:
            if not force:
                answer = click.confirm(
                    f"You don't have the utxo with {debt_amount} sat "
                    f"to pay the debt. Do you want it will be created?"
                )

                if not answer:
                    click.echo(
                        f"You must create an utxo with {debt_amount} manually "
                        f"to pay the debt"
                    )
                    return

            debt_utxo_info = make_utxo(
                rpc, debt_amount, vstage.plan.principal.asset
            )
        else:
            debt_utxo_info = parse_utxo_dict(debt_utxo)

    fee_amount = calculate_fee(rpc, DEBT_RETURN_TX_APPROX_SIZE)
    debt_in_btc = debt_amount if is_debt_in_btc else 0
    fee_utxo_info = get_fee_utxo(
        rpc, fee_amount + MIN_GUARANTEED_CHANGE + debt_in_btc, bitcoin_asset
    )
    fee_change_addr = CCoinConfidentialAddress(rpc.getnewaddress())
    debtor_return_addr = CCoinConfidentialAddress(rpc.getnewaddress())
    tx = return_debt_tx(
        vstage,
        creditor_control_asset,
        debtor_control_asset,
        bitcoin_asset,
        contract_tx=contract_tx_list[-1],
        debtor_control_tx=debtor_control_tx,
        fee_utxo_info=fee_utxo_info,
        fee_change_addr=fee_change_addr,
        debtor_return_addr=debtor_return_addr,
        fee_amount=fee_amount,
        debt_utxo_info=debt_utxo_info,
        is_full=full,
    )
    if not force:
        force = click.confirm(
            f"Do you want to send the {'full' if full else 'partial'} "
            f"transaction with fee {fee_amount}"
        )

    # sign with wallet non-contract inputs
    tx = sign_tx_with_wallet(rpc, tx)

    if force:
        txid = send_tx_with_confirm(rpc, tx)
        print(f"debt was returned, txid: {txid}")
    else:
        print_psbt(rpc, tx)


@debtor.command()
@rpc_option
@plan_option
@data_option
@click.option(
    "-o",
    "--output",
    type=click.Path(
        dir_okay=False,
        resolve_path=True,
        allow_dash=True,
    ),
    default="-",
    help="path to write the signature",
)
@min_output_option
@force_option
@network_option
def sign(rpc: ElementsRPCCaller, plan: str, data: str, output: str,
         min_output: int, force: bool, network: str) -> None:
    """Check and sign contract transaction"""
    select_chain_params(network)
    plandata = read_plandata(plan)
    debtor_data = read_aux_data(data)
    shared_blinding_xkey = CCoinExtKey(debtor_data["shared-blinding-xkey"])
    contract_tx = CElementsTransaction.deserialize(x(debtor_data["tx"]))
    repayment_plan = plandata.to_repayment_plan(min_output)
    contract_hash_preimage = shared_blinding_xkey.pub + str(
        repayment_plan.deterministic_representation()
    ).encode("utf-8")
    contract_hash = Uint256(hashlib.sha256(contract_hash_preimage).digest())

    if len(contract_tx.vout) < MIN_NUM_CONTRACT_OUTPUT:
        raise click.ClickException(
            f"contract tx with number of outputs < {MIN_NUM_CONTRACT_OUTPUT}"
        )

    if len(contract_tx.vin) < MIN_NUM_CONTRACT_INPUT:
        raise click.ClickException(
            f"contract tx with number of inputs < {MIN_NUM_CONTRACT_INPUT}"
        )

    cur_blockheight = rpc.getblockcount()
    if cur_blockheight > debtor_data["start-block-num"] and not force:
        raise click.ClickException(
            f"contract start block number is "
            f"{debtor_data['start-block-num']} "
            f"but current blockheight is {cur_blockheight}. "
            f"It is advised not to sign the contract transaction."
        )
    start_block_num = debtor_data["start-block-num"]
    blocks_to_start = start_block_num - cur_blockheight
    print(f"NOTE: contract will start after {blocks_to_start} blocks")

    # Make sure that the transaction is locked until the contract start
    if contract_tx.nLockTime != start_block_num:
        raise click.ClickException(
            "contract transaction nLockTime != start_block_num")

    bitcoin_asset = get_bitcoin_asset(rpc)
    if bitcoin_asset.to_hex() != debtor_data['bitcoin-asset']:
        raise click.ClickException(
            f"bitcoin asset mismatch: dumpassetlabels reports bitcoin asset "
            f"as {bitcoin_asset.to_hex()}, but debtor's data has "
            f"bitcoin asset as {debtor_data['bitcoin-asset']}")

    # Make sure that we will be signing the correct input
    collateral_utxo = get_utxo_by_outpoint(
        rpc, contract_tx.vin[CONTRACT_COLLATERAL_INP_INDEX].prevout
    )
    if collateral_utxo is None:
        raise click.ClickException("collateral asset utxo not found")

    debtor_control_asset = calculate_asset(
        generate_asset_entropy(
            contract_tx.vin[CONTRACT_COLLATERAL_INP_INDEX].prevout,
            contract_hash
        )
    )
    # Check:
    # 1) debtor_control_asset is sent to the address Bob controls
    asset = contract_tx.vout[
        CONTRACT_DEBTOR_CONTROL_OUT_INDEX
    ].nAsset.to_asset()

    if asset != debtor_control_asset:
        raise click.ClickException(
            f"output 3 does not contain debtor_control_asset "
            f"({debtor_control_asset.to_hex()}), but contains "
            f"{asset.to_hex()} instead"
        )

    if not is_scriptpubkey_mine(
        rpc, contract_tx.vout[CONTRACT_DEBTOR_CONTROL_OUT_INDEX].scriptPubKey
    ):
        raise click.ClickException("debtor control output address is not mine")

    # Check:
    # 2) The total amount of debtor_control_asset is 1, and there is no
    #    possible way that additional units of debtor_control_asset are
    #    issued, allowing others to take control of the Bob's side
    #    of the contract.
    error = check_issuance_amount_1_no_reissuance(
        contract_tx.vin[CONTRACT_COLLATERAL_INP_INDEX].assetIssuance,
        "debtor_control_asset",
    )
    if error is not None:
        raise click.ClickException(error)

    # Note that only the issuance amount check is actually necessary,
    # because Bob signs this input himself, and output amount cannot
    # be larger than what is issued. But we check output amount just in case.
    amount = contract_tx.vout[
        CONTRACT_DEBTOR_CONTROL_OUT_INDEX
    ].nValue.to_amount()

    if amount != 1:
        raise click.ClickException(
            f"unexpected debtor_control_asset amount in output: must be 1, "
            f"but it is {amount}"
        )
    # Check:
    # 3) All assets used in the contract are distinct -- no duplicates
    creditor_control_asset = CAsset(lx(debtor_data["creditor-control-asset"]))
    all_assets = (
        creditor_control_asset,
        debtor_control_asset,
        plandata.principal_asset,
        plandata.collateral_asset,
    )
    assert all(isinstance(asset, CAsset) for asset in all_assets)
    num_distinct_assets = len(set(all_assets))

    if num_distinct_assets != 4:
        raise click.ClickException(
            f"some asset is a duplicate: {all_assets}/{set(all_assets)}"
        )
    # 4) Pre-agreed amount of the principal asset sent to Bob's address
    debt_receive_script = contract_tx.vout[
        CONTRACT_PRINCIPAL_OUT_INDEX
    ].scriptPubKey
    debt_receive_addr_blinding_key = get_blinding_key_for_script(
        rpc, debt_receive_script
    )
    try:
        check_output(
            contract_tx,
            CONTRACT_PRINCIPAL_OUT_INDEX,
            debt_receive_addr_blinding_key,
            "principal",
            debt_receive_script,
            plandata.principal_asset,
            plandata.principal_amount,
        )
    except CheckOutputError as check_err:
        raise click.ClickException(check_err.message)
    # 5) If there's change output of collateral asset,
    # it is sent to Bob's address
    change_amount = (
        Amount(collateral_utxo["amount"]) - plandata.collateral_amount
    )
    OTHER_CONTRACT_IDX = MIN_NUM_CONTRACT_OUTPUT - 1
    if change_amount > 0:
        for txout_index_offset, txout in enumerate(
            contract_tx.vout[OTHER_CONTRACT_IDX:]
        ):
            if is_scriptpubkey_mine(rpc, txout.scriptPubKey):
                blinding_key = get_blinding_key_for_script(
                    rpc, txout.scriptPubKey
                )
                try:
                    check_output(
                        contract_tx,
                        OTHER_CONTRACT_IDX + txout_index_offset,
                        blinding_key,
                        "change",
                        txout.scriptPubKey,
                        plandata.collateral_asset,
                        change_amount,
                    )
                except CheckOutputError:
                    continue
                break
        else:
            raise click.ClickException("change output not found")

    # For checks 6) and 7) we need to generate the contract script
    # and revocation scripts.

    blinding_xkey = safe_derive(shared_blinding_xkey, LOCKED_COLLATERAL_PATH)

    # We need the blinding descriptor of collateral output
    # to create abl_contract_script
    unblind_result = contract_tx.vout[
        CONTRACT_COLLATERAL_OUT_INDEX
    ].unblind_confidential_pair(
        blinding_xkey.priv,
        contract_tx.wit.vtxoutwit[CONTRACT_COLLATERAL_OUT_INDEX].rangeproof,
    )

    if unblind_result.error:
        raise click.ClickException(
            f"cannot unblind locked collateral output: {unblind_result.error}"
        )

    with SafeDerivation():
        generate_abl_contract_for_lateral_stage(
            repayment_plan.first_lateral_stage,
            shared_blinding_xkey,
            start_block_num,
            creditor_control_asset,
            debtor_control_asset,
            bitcoin_asset,
            unblind_result.get_descriptor(),
        )

    first_vstage = repayment_plan.first_lateral_stage.vertical_stages[0]
    contract_addr = P2WSHCoinAddress.from_redeemScript(
        first_vstage.script_data.script
    )

    # Check:
    # 6) Pre-agreed amount of the collateral sent to the covenant address
    try:
        check_output(
            contract_tx,
            CONTRACT_COLLATERAL_OUT_INDEX,
            blinding_xkey.priv,
            "locked collateral",
            contract_addr.to_scriptPubKey(),
            plandata.collateral_asset,
            plandata.collateral_amount,
        )
    except CheckOutputError as check_err:
        raise click.ClickException(check_err.message)

    signedresult = rpc.signrawtransactionwithwallet(
        b2x(contract_tx.serialize()), [], "ALL|ANYONECANPAY"
    )
    contract_tx = CTransaction.deserialize(x(signedresult["hex"]))
    sign_data = {
        "signscript": b2x(
            contract_tx.vin[CONTRACT_COLLATERAL_INP_INDEX].scriptSig
        ),
        "witnessscript": b2x(
            contract_tx.wit.vtxinwit[CONTRACT_COLLATERAL_INP_INDEX].serialize()
        ),
    }
    with click.open_file(output, mode="x") as f:
        f.write(json.dumps(sign_data, indent=4))
    print(f"the sinature was saved to {output}")


@debtor.command()
@rpc_option
@click.option(
    "--principal-asset",
    type=AssetParamType(),
    help="principal asset",
    required=True,
)
@click.option(
    "--principal-amount",
    type=AmountParamType(),
    help="principal amount",
    required=True,
)
@click.option(
    "--collateral-asset",
    type=AssetParamType(),
    help="collateral asset",
    required=True,
)
@click.option(
    "--collateral-amount",
    type=AmountParamType(),
    help="collateral amount",
    required=True,
)
@click.option(
    "--collateral-amount-unconditionally-forfeited",
    type=AmountParamType(),
    help="collateral amount unconfitionally forfeited on debtor's default",
    required=True,
)
@click.option(
    "--total-periods",
    type=int,
    help="total periods",
    required=True,
)
@click.option(
    "--total-steps",
    type=int,
    help="total steps",
    required=True,
)
@click.option(
    "--rate-due",
    type=Decimal,
    help="regular repayment rate",
    required=True,
)
@click.option(
    "--rate-early",
    type=Decimal,
    help="early repayment rate",
    required=True,
)
@click.option(
    "--num-blocks-in-period",
    type=int,
    help="num blocks in period",
    required=True,
)
@click.option(
    "--rates-late",
    cls=RateListOption,
    help="late repayment rates",
    required=True
)
@click.option(
    "--rate-collateral-penalty",
    type=Decimal,
    help="collateral penalty rate",
    required=True,
)
@click.option(
    "-op",
    "--output-plan",
    type=click.Path(
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
        allow_dash=True,
    ),
    default="-",
    required=True,
    help="path to plan",
)
@click.option(
    "-oi",
    "--output-info",
    type=click.Path(
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
        allow_dash=False,
    ),
    required=True,
    help="path to info",
)
@network_option
def make(
    rpc: ElementsRPCCaller,
    principal_asset: CAsset,
    principal_amount: Amount,
    collateral_asset: CAsset,
    collateral_amount: Amount,
    collateral_amount_unconditionally_forfeited: Amount,
    total_periods: int,
    total_steps: int,
    rate_due: Decimal,
    rate_early: Decimal,
    num_blocks_in_period: int,
    rates_late: List[Decimal],
    rate_collateral_penalty: Decimal,
    output_plan: str,
    output_info: str,
    network: str
) -> None:
    """Create repayment plan"""

    select_chain_params(network)

    if not asset_amount_is_enough(rpc, collateral_amount, collateral_asset):
        raise click.ClickException(
            f"Balance of asset {collateral_asset.to_hex()} is insufficient"
        )

    result = validate_total_periods(total_periods)
    if isinstance(result, ValidationFailure):
        raise click.ClickException(result.error)

    result = validate_num_blocks_in_period(num_blocks_in_period)
    if isinstance(result, ValidationFailure):
        raise click.ClickException(result.error)

    rates_for_checking = {
        "rate-due": rate_due,
        "rate-early": rate_early,
    }
    rates_for_checking.update(
        {
            f"rates-late-{n}": value
            for n, value in enumerate(rates_late)
        }
    )
    for rate_name, rate in rates_for_checking.items():
        result = validate_rate(rate, rate_name)
        if isinstance(result, ValidationFailure):
            raise click.ClickException(result.error)

    result = validate_total_steps(total_steps, total_periods,
                                  len(rates_late)+1)
    if isinstance(result, ValidationFailure):
        raise click.ClickException(result.error)

    plandata = PlanData(
        principal_asset=principal_asset,
        principal_amount=principal_amount,
        collateral_asset=collateral_asset,
        collateral_amount=collateral_amount,
        N=total_periods,
        S=total_steps,
        rates=Rates(rate_due=rate_due, rate_early=rate_early,
                    rate_collateral_penalty=rate_collateral_penalty,
                    rates_late=rates_late),
        num_blocks_in_period=num_blocks_in_period,
        amount_C_uncond=collateral_amount_unconditionally_forfeited
    )
    utxo = find_blinded_asset_utxo_by_min_amount(
        rpc, collateral_asset, collateral_amount
    )
    if utxo is None:
        raise click.ClickException(
            f"Can't find utxo with amount {collateral_amount} satoshi "
            f"you'll need to consolidate the funds first, so that "
            f"there is an UTXO with the requested amount")

    collateral_asset_addr = rpc.getaddressinfo(utxo["address"])["confidential"]
    debtor_control_addr = rpc.getnewaddress()
    debtor_change_addr = rpc.getnewaddress()
    debtor_receive_addr = rpc.getnewaddress()
    collateral_asset_blinding_key = rpc.dumpblindingkey(collateral_asset_addr)
    collateral_info = dict(
        txid=utxo["txid"],
        vout_index=utxo["vout"],
        blinding_key=collateral_asset_blinding_key,
        control_addr=debtor_control_addr,
        collateral_change_addr=debtor_change_addr,
        receive_addr=debtor_receive_addr,
    )
    save_to_json_with_hash(output_info, collateral_info)
    with click.open_file(output_plan, mode="x") as f:
        f.write(plandata.to_json())

    print(f"repayment plan was saved to {output_plan}")
    print(f"collateral info was saved to {output_info}")


@debtor.command()
@rpc_option
@plan_option
@click.option(
    "-o",
    "--output",
    type=click.Path(
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
        allow_dash=True,
    ),
    default="-",
    help="path to info",
)
@network_option
def accept(rpc: ElementsRPCCaller, plan: str, output: str, network: str
           ) -> None:
    """Accept repayment plan"""
    select_chain_params(network)
    plandata = read_plandata(plan)

    if not asset_amount_is_enough(
        rpc, plandata.collateral_amount, plandata.collateral_asset
    ):
        raise click.ClickException(
            f"Balance of asset {plandata.collateral_asset.to_hex()} "
            f"is insufficient"
        )

    utxo = find_asset_utxo_by_min_amount(
        rpc, plandata.collateral_asset, plandata.collateral_amount
    )
    if utxo is None:
        raise click.ClickException(
            f"Can't find utxo with amount {plandata.collateral_amount} "
            f"satoshi, you'll need to consolidate the funds first, so that "
            f"there is an UTXO with the requested amount")

    collateral_asset_addr = rpc.getaddressinfo(utxo["address"])["confidential"]
    debtor_control_addr = rpc.getnewaddress()
    debtor_change_addr = rpc.getnewaddress()
    debtor_receive_addr = rpc.getnewaddress()
    collateral_asset_blinding_key = rpc.dumpblindingkey(collateral_asset_addr)
    collateral_info = dict(
        txid=utxo["txid"],
        vout_index=utxo["vout"],
        blinding_key=collateral_asset_blinding_key,
        control_addr=debtor_control_addr,
        collateral_change_addr=debtor_change_addr,
        receive_addr=debtor_receive_addr,
    )
    save_to_json_with_hash(output, collateral_info)
    print(f"collateral info was saved to {output}")


if __name__ == "__main__":
    debtor()
