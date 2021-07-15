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
from bitcointx.core import CTransaction, b2lx, b2x, lx, x, Uint256
from bitcointx.core.script import CScript
from bitcointx.wallet import CCoinAddress, CCoinExtKey, P2WSHCoinAddress

from elementstx.core import (
    CElementsTransaction,
    CElementsMutableTransaction,
    CAsset,
    calculate_asset,
    generate_asset_entropy,
    CElementsMutableTxIn,
    CElementsMutableTxWitness,
    CElementsMutableTxInWitness,
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
    BLIND_PUB_COLLATERAL_RETURN_TX_PATH,
    BLIND_PUB_PAYMENT_RETURN_DEBT_TX_PATH,
    COMMON_TX_APPROX_SIZE,
    CONTRACT_PRINCIPAL_INP_INDEX,
    CONTRACT_COLLATERAL_INP_INDEX,
    CONTRACT_COLLATERAL_OUT_INDEX,
    CONTRACT_CREDITOR_CONTROL_OUT_INDEX,
    MUTUAL_DEBTOR_OUT_INDEX,
    LOCKED_COLLATERAL_PATH,
    MIN_GUARANTEED_CHANGE,
    MIN_NUM_CONTRACT_INPUT,
    MIN_NUM_CONTRACT_OUTPUT,
)
from lib.loan_utils import create_mutual_spend_transaction
from lib.loan_utils import grab_collateral_tx
from lib.loan_utils import revoke_debt_return_window_tx
from lib.loan_utils import spend_via_control_asset_tx
from lib.rpc_utils import (
    calculate_fee,
    find_all_payments,
    find_asset_utxo_by_min_amount,
    find_blinded_asset_utxo_by_min_amount,
    get_blinding_key_for_script,
    get_fee_utxo,
    get_utxo_by_outpoint,
    is_scriptpubkey_mine,
    sign_tx_with_wallet,
    track_contract_txs,
    get_bitcoin_asset
)
from lib.types import (
    Amount, AmountParamType, AssetParamType, PlanData, RepaymentPlan,
    CheckOutputError, Rates, RateListOption, CreditorAsset, DebtorAsset,
    BitcoinAsset, ContractTransaction, VerticalProgressionStage,
    ElementsRPCCaller
)
from lib.utils import (
    find_explicit_asset_txout_index, safe_derive, SafeDerivation
)
from lib.validators import (
    ValidationFailure,
    validate_num_blocks_in_period,
    validate_rate,
    validate_total_periods,
    validate_total_steps,
)
from lib.generator import generate_abl_contract_for_lateral_stage


def compute_info(
    rpc: ElementsRPCCaller,
    creditor_data: Dict[str, Any],
    plandata: PlanData,
    min_output: int,
    cache_dir: Optional[Path] = None,
) -> Tuple[RepaymentPlan,
           List[ContractTransaction], List[VerticalProgressionStage],
           CreditorAsset, DebtorAsset, BitcoinAsset]:
    shared_blinding_xkey = CCoinExtKey(creditor_data["shared-blinding-xkey"])
    current_block = rpc.getblockchaininfo()["blocks"]
    first_contract_tx = CElementsMutableTransaction.deserialize(
        x(creditor_data["tx"]))
    principal_input = first_contract_tx.vin[CONTRACT_PRINCIPAL_INP_INDEX]

    repayment_plan = plandata.to_repayment_plan(min_output)

    contract_hash_preimage = shared_blinding_xkey.pub + str(
        repayment_plan.deterministic_representation()
    ).encode("utf-8")
    contract_hash = Uint256(hashlib.sha256(contract_hash_preimage).digest())
    creditor_control_asset = calculate_asset(
        generate_asset_entropy(principal_input.prevout, contract_hash)
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

    bitcoin_asset = get_bitcoin_asset(rpc)
    debtor_control_asset = CAsset(lx(creditor_data["debtor-control-asset"]))

    with SafeDerivation():
        generate_abl_contract_for_lateral_stage(
            repayment_plan.first_lateral_stage,
            shared_blinding_xkey,
            creditor_data["start-block-num"],
            creditor_control_asset,
            debtor_control_asset,
            bitcoin_asset,
            unblind_result.get_descriptor(),
        )

    contract_tx_list, vstage_list = track_contract_txs(
        b2lx(principal_input.prevout.hash),
        rpc,
        prev_txout_index=principal_input.prevout.n,
        from_block=creditor_data['start-block-num'],
        to_block=current_block,
        plan=repayment_plan
    )

    cmp_tx = contract_tx_list[0].to_mutable()
    cmp_tx.wit = CElementsMutableTxWitness()

    for inp in cmp_tx.vin:
        inp.scriptSig = CScript()

    first_contract_tx.wit = CElementsMutableTxWitness()
    first_contract_tx.vin[CONTRACT_COLLATERAL_INP_INDEX] = \
        cmp_tx.vin[CONTRACT_COLLATERAL_INP_INDEX]

    if cmp_tx.serialize() != first_contract_tx.serialize():
        raise click.ClickException(
            f"transaction {b2lx(contract_tx_list[0].GetTxid())} found "
            f"in blockchain does not correspond to the transaction stored "
            f"in creditor's data"
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
def creditor() -> None:
    ...


@creditor.command()
@rpc_option
@click.option(
    "--debt",
    "debt_amount",
    type=AmountParamType(),
    help="debt amount you want to get",
    required=True,
)
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
@force_option
@network_option
def signmutual(rpc: ElementsRPCCaller, debt_amount: Amount,
               tx_data: str, force: bool, network: str) -> None:
    """Sign mutual-spend transaction"""
    select_chain_params(network)
    with click.open_file(tx_data) as f:
        mutual_tx = CElementsTransaction.deserialize(x(f.read()))
    unblinded_tx_result = rpc.unblindrawtransaction(b2x(mutual_tx.serialize()))
    unblinded_tx = CElementsTransaction.deserialize(
        x(unblinded_tx_result["hex"])
    ).to_mutable()
    if (
        unblinded_tx.vout[MUTUAL_DEBTOR_OUT_INDEX].nValue.to_amount()
        != debt_amount
    ):
        raise click.ClickException(
            f"Unexpected debt amount "
            f"{unblinded_tx.vout[MUTUAL_DEBTOR_OUT_INDEX].nValue.to_amount()}"
        )
    if not force:
        force = click.confirm("Do you want to send the transaction?")

    tx = sign_tx_with_wallet(rpc, mutual_tx)
    if force:
        txid = send_tx_with_confirm(rpc, tx)
        click.echo(f"the transaction data was sent: txid={txid}")
    else:
        print_psbt(rpc, tx)


@creditor.command()
@rpc_option
@plan_option
@data_option
@click.option(
    "--debt",
    "debt_amount",
    type=AmountParamType(),
    help="debt amount you want to get",
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
    help="path to write transaction data",
)
@min_output_option
@network_option
def createmutual(rpc: ElementsRPCCaller, plan: str, data: str,
                 debt_amount: Amount, output: str, min_output: int,
                 network: str) -> None:
    """Create mutual-spend transaction"""
    select_chain_params(network)
    creditor_data = read_aux_data(data)
    (
        repayment_plan,
        contract_tx_list,
        vstage_list,
        creditor_control_asset,
        debtor_control_asset,
        bitcoin_asset,
    ) = compute_info(rpc, creditor_data, read_plandata(plan), min_output,
                     Path(plan).parent)

    if len(contract_tx_list) != len(vstage_list) is None:
        raise click.ClickException(
            "Contract seems to be finished, cannot create mutual-spend "
            "transaction")

    last_creditor_ctrl_utxo = find_asset_utxo_by_min_amount(
        rpc, creditor_control_asset, 0
    )

    if last_creditor_ctrl_utxo is None:
        raise click.ClickException("Can't find creditor control asset")

    creditor_control_tx = CElementsTransaction.deserialize(
        x(rpc.getrawtransaction(last_creditor_ctrl_utxo["txid"]))
    )

    creditor_control_txout_index = find_explicit_asset_txout_index(
        creditor_control_tx, creditor_control_asset
    )

    vstage = vstage_list[-1]
    last_contract_tx = contract_tx_list[-1]

    debt_return_address = CCoinConfidentialAddress(rpc.getnewaddress())

    mutual_tx, pubkeys = create_mutual_spend_transaction(
        vstage,
        creditor_control_asset,
        debtor_control_asset,
        last_contract_tx,
        principal_to_creditor_amount=debt_amount,
        principal_to_creditor_addr=debt_return_address,
    )

    mutual_tx.vin.append(
        CElementsMutableTxIn(
            CElementsOutPoint(
                hash=creditor_control_tx.GetTxid(),
                n=creditor_control_txout_index,
            )
        )
    )
    mutual_tx.wit.vtxinwit.append(CElementsMutableTxInWitness())

    out_data = json.dumps(
        {"hex": b2x(mutual_tx.serialize()),
         "pubkeys": [b2x(pub) for pub in pubkeys]}
    )
    with click.open_file(output, mode="x") as f:
        f.write(out_data)

    print(f"the transaction data was saved to {output}")


@creditor.command()
@rpc_option
@plan_option
@data_option
@min_output_option
@force_option
@network_option
def getpayment(rpc: ElementsRPCCaller, plan: str, data: str,
               min_output: int, force: bool, network: str) -> None:
    """Claim the payment sent by the debtor"""
    select_chain_params(network)
    plandata = read_plandata(plan)
    creditor_data = read_aux_data(data)
    (
        repayment_plan,
        contract_tx_list,
        vstage_list,
        creditor_control_asset,
        debtor_control_asset,
        bitcoin_asset,
    ) = compute_info(rpc, creditor_data, read_plandata(plan), min_output,
                     Path(plan).parent)

    last_creditor_ctrl_utxo = find_asset_utxo_by_min_amount(
        rpc, creditor_control_asset, 0
    )

    if last_creditor_ctrl_utxo is None:
        raise click.ClickException("Can't find creditor control asset")

    creditor_control_tx = CTransaction.deserialize(
        x(rpc.getrawtransaction(last_creditor_ctrl_utxo["txid"]))
    )

    payments_list = find_all_payments(
        contract_tx_list,
        creditor_control_asset,
        rpc
    )

    if not payments_list:
        raise click.ClickException("Can't find any payment")

    payment_txid, vout_index, tx_idx = payments_list[0]

    payment_tx_dict = rpc.getrawtransaction(payment_txid, 1)
    payment_tx = CElementsTransaction.deserialize(x(payment_tx_dict["hex"]))

    if tx_idx >= len(vstage_list):
        vstage = vstage_list[-1]
        return_amount = vstage.full_repayment_amount
        payment_type = "full"
        unblind_key_path = BLIND_PUB_COLLATERAL_RETURN_TX_PATH
        is_final = True
        # the control asset is burnt in full repayment
        control_asset_return_addr = None
    else:
        vstage = vstage_list[tx_idx-1]
        return_amount = vstage.regular_repayment_amount
        payment_type = "partial"
        unblind_key_path = BLIND_PUB_PAYMENT_RETURN_DEBT_TX_PATH
        is_final = False
        control_asset_return_addr = CCoinAddress(rpc.getnewaddress())

    unblind_result = payment_tx.vout[vout_index].unblind_confidential_pair(
        safe_derive(vstage.blinding_data.blinding_xkey, unblind_key_path).priv,
        payment_tx.wit.vtxoutwit[vout_index].rangeproof,
    )
    if unblind_result.error:
        raise click.ClickException(
            f"cannot unblind locked output: {unblind_result.error}"
        )

    if unblind_result.asset == plandata.principal_asset:
        if unblind_result.amount != return_amount:
            raise click.ClickException(
                f"the {unblind_result.amount} return amount"
                f" is not excepted {return_amount}"
            )

    fee_amount = calculate_fee(rpc, COMMON_TX_APPROX_SIZE)
    fee_utxo_info = get_fee_utxo(rpc, fee_amount + MIN_GUARANTEED_CHANGE,
                                 bitcoin_asset)
    dst_addr = CCoinConfidentialAddress(rpc.getnewaddress())
    fee_change_addr = CCoinConfidentialAddress(rpc.getnewaddress())
    tx = spend_via_control_asset_tx(
        amount=unblind_result.amount,
        src_tx=payment_tx,
        src_txout_index=vout_index,
        src_input_descriptor=unblind_result.get_descriptor(),
        control_asset=creditor_control_asset,
        control_tx=creditor_control_tx,
        fee_utxo_info=fee_utxo_info,
        fee_amount=fee_amount,
        dst_addr=dst_addr,
        fee_change_addr=fee_change_addr,
        control_asset_return_addr=control_asset_return_addr,
        is_final=is_final,
        bitcoin_asset=bitcoin_asset
    )

    if not force:
        force = click.confirm(
            f"Do you want to send the transaction"
            f" with fee {fee_amount} sat to get the payment"
            f" (amount = {unblind_result.amount})?"
        )

    tx = sign_tx_with_wallet(rpc, tx)
    if force:
        txid = send_tx_with_confirm(rpc, tx)
        print(
            f"Successfully claimed the {payment_type} repayment "
            f"via control asset, txid = {txid}"
        )
        print(
            f"Payment was spent to your address: {dst_addr}"
            f", amount {return_amount}"
        )
    else:
        print_psbt(rpc, tx)


@creditor.command()
@rpc_option
@plan_option
@data_option
@min_output_option
@force_option
@network_option
def revokewindow(rpc: ElementsRPCCaller, plan: str, data: str,
                 min_output: int, force: bool, network: str) -> None:
    """Revoke the payment window"""
    select_chain_params(network)
    creditor_data = read_aux_data(data)
    current_block = rpc.getblockchaininfo()["blocks"]
    (
        repayment_plan,
        contract_tx_list,
        vstage_list,
        creditor_control_asset,
        debtor_control_asset,
        bitcoin_asset,
    ) = compute_info(rpc, creditor_data, read_plandata(plan), min_output,
                     Path(plan).parent)

    if len(contract_tx_list) != len(vstage_list) is None:
        raise click.ClickException(
            "Contract seems to be finished, cannot revoke the "
            "payment window")

    last_creditor_ctrl_utxo = find_asset_utxo_by_min_amount(
        rpc, creditor_control_asset, 0
    )

    if last_creditor_ctrl_utxo is None:
        raise click.ClickException("Can't find creditor control asset")

    creditor_control_tx = CElementsTransaction.deserialize(
        x(rpc.getrawtransaction(last_creditor_ctrl_utxo["txid"]))
    )

    vstage = vstage_list[-1]
    last_contract_tx = contract_tx_list[-1]

    lstage = vstage.parent_lateral_stage
    # check timeout
    timeout_blocks = (
        lstage.level_n + vstage.index_m + 1
    ) * vstage.plan.num_blocks_in_period
    target_block = timeout_blocks + creditor_data["start-block-num"]
    if target_block > current_block:
        raise click.ClickException(
            f"You can't revoke window at {current_block} block,"
            f"you must wait to {target_block} block"
        )
    if vstage.index_m == len(lstage.vertical_stages) - 1:
        # Grab collaterall
        payments_list = find_all_payments(
            contract_tx_list,
            creditor_control_asset,
            rpc
        )
        if payments_list:
            raise click.ClickException("You have unclaimed payments, "
                                       "you can't grab the collateral now")

        grab_dst_addr = CCoinConfidentialAddress(rpc.getnewaddress())

        fee_amount = calculate_fee(rpc, COMMON_TX_APPROX_SIZE)
        fee_utxo_info = get_fee_utxo(
            rpc, fee_amount + MIN_GUARANTEED_CHANGE, bitcoin_asset)
        fee_change_addr = CCoinConfidentialAddress(rpc.getnewaddress())
        grab_tx = grab_collateral_tx(
            vstage,
            creditor_control_asset,
            debtor_control_asset,
            bitcoin_asset,
            fee_utxo_info=fee_utxo_info,
            fee_amount=fee_amount,
            fee_change_addr=fee_change_addr,
            grab_dst_addr=grab_dst_addr,
            contract_tx=last_contract_tx,
            creditor_control_tx=creditor_control_tx,
            start_block_num=creditor_data["start-block-num"]
        )
        if not force:
            force = click.confirm("Do you want to send the grab transaction?")

        grab_tx = sign_tx_with_wallet(rpc, grab_tx)
        if force:
            grab_txid = send_tx_with_confirm(rpc, grab_tx)
        else:
            print_psbt(rpc, grab_tx)
            return

        print(f"the collaterall was grabbed: {grab_txid}")
        print(f"the collaterall was sent to your address: {grab_dst_addr}")
    else:
        fee_amount = calculate_fee(rpc, COMMON_TX_APPROX_SIZE)
        fee_utxo_info = get_fee_utxo(
            rpc, fee_amount + MIN_GUARANTEED_CHANGE, bitcoin_asset)
        fee_change_addr = CCoinConfidentialAddress(rpc.getnewaddress())
        creditor_ctrl_return_addr = CCoinConfidentialAddress(
            rpc.getnewaddress())
        revoke_tx = revoke_debt_return_window_tx(
            vstage,
            creditor_control_asset,
            bitcoin_asset,
            fee_utxo_info=fee_utxo_info,
            fee_amount=fee_amount,
            fee_change_addr=fee_change_addr,
            creditor_ctrl_return_addr=creditor_ctrl_return_addr,
            contract_tx=last_contract_tx,
            creditor_control_tx=creditor_control_tx,
            start_block_num=creditor_data["start-block-num"]

        )
        if not force:
            force = click.confirm(
                "Do you want to send the revoking transaction?"
            )

        revoke_tx = sign_tx_with_wallet(rpc, revoke_tx)
        if force:
            txid = send_tx_with_confirm(rpc, revoke_tx)
        else:
            print_psbt(rpc, revoke_tx)
            return

        click.echo(f"the window was revoked: txid={txid}")


@creditor.command()
@rpc_option
@plan_option
@data_option
@force_option
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
@network_option
def sign(rpc: ElementsRPCCaller, plan: str, data: str, output: click.Path,
         min_output: int, force: bool, network: str)-> None:
    """Check and sign contract transaction"""
    select_chain_params(network)
    plandata = read_plandata(plan)
    creditor_data = read_aux_data(data)
    shared_blinding_xkey = CCoinExtKey(creditor_data["shared-blinding-xkey"])
    contract_tx = CElementsTransaction.deserialize(x(creditor_data["tx"]))
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
    if cur_blockheight > creditor_data["start-block-num"] and not force:
        raise click.ClickException(
            f"contract start block number is "
            f"{creditor_data['start-block-num']} "
            f"but current blockheight is {cur_blockheight}. "
            f"It is advised not to sign the contract transaction."
        )
    start_block_num = creditor_data["start-block-num"]
    blocks_to_start = start_block_num - cur_blockheight
    print(f"NOTE: contract will start after {blocks_to_start} blocks")

    # Make sure that the transaction is locked until the contract start
    if contract_tx.nLockTime != start_block_num:
        raise click.ClickException(
            "contract transaction nLockTime != start_block_num")

    bitcoin_asset = get_bitcoin_asset(rpc)
    if bitcoin_asset.to_hex() != creditor_data['bitcoin-asset']:
        raise click.ClickException(
            f"bitcoin asset mismatch: dumpassetlabels reports bitcoin asset "
            f"as {bitcoin_asset.to_hex()}, but creditor's data has "
            f"bitcoin asset as {creditor_data['bitcoin-asset']}")

    # Make sure that we will be signing the correct input
    principal_utxo = get_utxo_by_outpoint(
        rpc, contract_tx.vin[CONTRACT_PRINCIPAL_INP_INDEX].prevout
    )
    if principal_utxo is None:
        raise click.ClickException("principal asset utxo not found")

    creditor_control_asset = calculate_asset(
        generate_asset_entropy(
            contract_tx.vin[CONTRACT_PRINCIPAL_INP_INDEX].prevout,
            contract_hash
        )
    )

    # Check:
    # 1) creditor_control_asset is sent to the address Alice controls
    asset = contract_tx.vout[
        CONTRACT_CREDITOR_CONTROL_OUT_INDEX
    ].nAsset.to_asset()

    if asset != creditor_control_asset:
        raise click.ClickException(
            f"output {CONTRACT_CREDITOR_CONTROL_OUT_INDEX} does not contain "
            f"creditor_control_asset ({creditor_control_asset.to_hex()}), "
            f"but contains {asset.to_hex()} instead"
        )

    if not is_scriptpubkey_mine(
        rpc, contract_tx.vout[CONTRACT_CREDITOR_CONTROL_OUT_INDEX].scriptPubKey
    ):
        raise click.ClickException(
            "creditor control output address is not mine"
        )

    # Check:
    # 2) The total amount of creditor_control_asset is 1, and there is no
    #    possible way that additional units of creditor_control_asset are
    #    (re)issued, allowing others to take control of the Alice's side
    #    of the contract.
    error = check_issuance_amount_1_no_reissuance(
        contract_tx.vin[CONTRACT_PRINCIPAL_INP_INDEX].assetIssuance,
        "creditor_control_asset",
    )
    if error is not None:
        raise click.ClickException(error)

    # Note that only the issuance amount check is actually necessary,
    # because Alice signs this input herself, and output amount cannot
    # be larger than what is issued. But we check output amount just in case.
    amount = contract_tx.vout[
        CONTRACT_CREDITOR_CONTROL_OUT_INDEX
    ].nValue.to_amount()

    if amount != 1:
        raise click.ClickException(
            f"unexpected creditor_control_asset amount in output: must be 1, "
            f"but it is {amount}"
        )

    # Check:
    # 3) All assets used in the contract are distinct -- no duplicates
    debtor_control_asset = CAsset(lx(creditor_data["debtor-control-asset"]))
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

    assert isinstance(principal_utxo["amount"], Decimal)
    change_amount = (
        Amount(principal_utxo["amount"]) - plandata.principal_amount
    )
    # Check:
    # 5) If there's change output of principal asset, it is sent
    # to Alice's address
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
                        plandata.principal_asset,
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
            creditor_data["start-block-num"],
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
            contract_tx.vin[CONTRACT_PRINCIPAL_INP_INDEX].scriptSig
        ),
        "witnessscript": b2x(
            contract_tx.wit.vtxinwit[CONTRACT_PRINCIPAL_INP_INDEX].serialize()
        ),
    }
    with click.open_file(output, mode="x") as f:
        f.write(json.dumps(sign_data, indent=4))

    print(f"the sinature was saved to {output}")


@creditor.command()
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
    "-oi",
    "--output-info",
    type=click.Path(
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
        allow_dash=False,
    ),
    required=True,
    help="path to principal info",
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
    output_info: str,
    output_plan: str,
    network: str,
) -> None:
    """Create repayment plan"""
    select_chain_params(network)
    if not asset_amount_is_enough(rpc, principal_amount, principal_asset):
        raise click.ClickException(
            f"Balance of asset {principal_asset.to_hex()} is insufficient"
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

    repayment_plan = PlanData(
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
    principal_asset_addr = rpc.getnewaddress()
    utxo = find_blinded_asset_utxo_by_min_amount(
        rpc, principal_asset, principal_amount
    )
    if utxo is None:
        raise click.ClickException(
            f"Can't find utxo with amount {principal_amount} satoshi "
            f"you'll need to consolidate the funds first, so that "
            f"there is an UTXO with the requested amount")
    addressinfo = rpc.getaddressinfo(utxo["address"])
    if "confidential" not in addressinfo:
        raise click.ClickException("principal utxo is not confidential")
    principal_asset_addr = addressinfo["confidential"]
    creditor_control_addr = rpc.getnewaddress()
    creditor_change_addr = rpc.getnewaddress()
    principal_asset_blinding_key = rpc.dumpblindingkey(principal_asset_addr)
    principal_info = dict(
        txid=utxo["txid"],
        vout_index=utxo["vout"],
        blinding_key=principal_asset_blinding_key,
        control_addr=creditor_control_addr,
        principal_change_addr=creditor_change_addr,
    )
    save_to_json_with_hash(output_info, principal_info)
    with click.open_file(output_plan, mode="x") as f:
        f.write(repayment_plan.to_json())

    print(f"repayment plan was saved to {output_plan}")
    print(f"principal info was saved to {output_info}")


if __name__ == "__main__":
    creditor()
