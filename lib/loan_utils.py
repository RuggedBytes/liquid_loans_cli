# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import hashlib
import os
from io import BytesIO
from typing import List, Optional, Tuple

from bitcointx.core import (
    CMutableTransaction,
    COutPoint,
    CTxIn,
    Uint256,
)
from bitcointx.core.key import CPubKey
from bitcointx.core.script import OP_RETURN, CScript
from bitcointx.wallet import CCoinAddress, CCoinExtKey, P2WSHCoinAddress
from elementstx.core import (
    CElementsMutableTransaction,
    BlindingInputDescriptor,
    CAsset,
    CAssetIssuance,
    CConfidentialAsset,
    CConfidentialValue,
    calculate_asset,
    generate_asset_entropy,
    CElementsTransaction,
    CElementsTxOut,
    CElementsMutableTxOut,
    CElementsTxIn,
    CElementsOutPoint,
    CElementsMutableTxOutWitness,
)
from elementstx.wallet import CCoinConfidentialAddress

from .builders import (
    build_grab_transaction,
    build_partial_repayment_transaction,
    build_full_repayment_transaction,
    build_revocation_transaction,
)
from .constants import (
    CONTRACT_COLLATERAL_OUT_INDEX,
    LOCKED_COLLATERAL_PATH,
    RANDOM_BYTES_PER_UNIT_BLINDING,
    SEED_CONTRACT_TX_PATH,
)
from .generator import generate_abl_contract_for_lateral_stage, get_dummy_addr
from .scripts import get_control_script
from .sign import sign_for_covenant
from .types import (
    ContractMutableTransaction,
    Amount,
    BlindedInputInfo,
    CreditorLoanStartInfo,
    DebtorLoanStartInfo,
    RepaymentPlan,
    VerticalProgressionStage,
    CreditorAsset,
    DebtorAsset,
    BitcoinAsset,
)
from .utils import (
    blind_tx_and_validate,
    find_explicit_asset_txout_index,
    make_block_cprng, safe_derive
)


def create_loan_transaction(
    repayment_plan: RepaymentPlan,
    creditor_info: CreditorLoanStartInfo,
    debtor_info: DebtorLoanStartInfo,
    shared_blinding_xkey: CCoinExtKey,
    fee_utxo_info: BlindedInputInfo,
    fee_change_addr: CCoinConfidentialAddress,
    bitcoin_asset: BitcoinAsset,
    *,
    start_block_num: int,
    fee_amount: int,
) -> Tuple[CMutableTransaction, CreditorAsset, DebtorAsset]:
    assert start_block_num > 0

    contract_dummy_addr = get_dummy_addr()

    contract_hash_preimage = shared_blinding_xkey.pub + str(
        repayment_plan.deterministic_representation()
    ).encode("utf-8")

    contract_hash = Uint256(hashlib.sha256(contract_hash_preimage).digest())

    principal_asset_outpoint = CElementsOutPoint(creditor_info.tx.GetTxid(),
                                                 creditor_info.vout_index)

    creditor_control_asset = CreditorAsset(
        calculate_asset(
            generate_asset_entropy(principal_asset_outpoint, contract_hash)
        ).data
    )

    collateral_asset_outpoint = CElementsOutPoint(debtor_info.tx.GetTxid(),
                                                  debtor_info.vout_index)

    debtor_control_asset = DebtorAsset(
        calculate_asset(
            generate_asset_entropy(collateral_asset_outpoint, contract_hash)
        ).data
    )

    assert fee_utxo_info.blinding_input_descriptor.amount is not None
    assert fee_amount is not None
    fee_change_amount = (
        fee_utxo_info.blinding_input_descriptor.amount - fee_amount
    )

    tx = CElementsMutableTransaction(
        vin=[
            CElementsTxIn(
                collateral_asset_outpoint,
                assetIssuance=CAssetIssuance(
                    assetEntropy=contract_hash, nAmount=CConfidentialValue(1)
                ),
            ),
            CElementsTxIn(
                principal_asset_outpoint,
                assetIssuance=CAssetIssuance(
                    assetEntropy=contract_hash, nAmount=CConfidentialValue(1)
                ),
            ),
            CTxIn(fee_utxo_info.outpoint,
                  nSequence=0xFFFFFFFE)  # enable nLockTime check
        ],
        vout=[
            CElementsTxOut(
                nValue=CConfidentialValue(repayment_plan.collateral.amount),
                nAsset=CConfidentialAsset(repayment_plan.collateral.asset),
                # dummy address will be replaced with contract address
                scriptPubKey=contract_dummy_addr.to_scriptPubKey(),
            ),
            CElementsTxOut(
                nValue=CConfidentialValue(repayment_plan.principal.amount),
                nAsset=CConfidentialAsset(repayment_plan.principal.asset),
                scriptPubKey=debtor_info.receive_addr.to_scriptPubKey(),
            ),
            CElementsTxOut(
                nValue=CConfidentialValue(1),
                nAsset=CConfidentialAsset(creditor_control_asset),
                scriptPubKey=creditor_info.control_addr.to_scriptPubKey(),
            ),
            CElementsTxOut(
                nValue=CConfidentialValue(1),
                nAsset=CConfidentialAsset(debtor_control_asset),
                scriptPubKey=debtor_info.control_addr.to_scriptPubKey(),
            ),
        ],
        nLockTime=start_block_num
    )

    output_pubkeys = [
        safe_derive(shared_blinding_xkey, LOCKED_COLLATERAL_PATH).pub,
        debtor_info.receive_addr.blinding_pubkey,
        CPubKey(),
        CPubKey(),
    ]

    fee_asset = fee_utxo_info.blinding_input_descriptor.asset

    if fee_change_amount > 0:
        tx.vout.append(
            CElementsMutableTxOut(
                # change from the input used to pay the fee
                nValue=CConfidentialValue(fee_change_amount),
                nAsset=CConfidentialAsset(fee_asset),
                scriptPubKey=fee_change_addr.to_scriptPubKey(),
            )
        )
        output_pubkeys.append(fee_change_addr.blinding_pubkey)

    tx.vout.append(
        CElementsMutableTxOut(
            nValue=CConfidentialValue(fee_amount),
            nAsset=CConfidentialAsset(fee_asset),
        )
    )
    output_pubkeys.append(CPubKey())

    principal_change_amount = (
        creditor_info.principal_amount - repayment_plan.principal.amount
    )

    if principal_change_amount > 0:
        tx.vout.append(
            CElementsMutableTxOut(
                nValue=CConfidentialValue(principal_change_amount),
                nAsset=CConfidentialAsset(repayment_plan.principal.asset),
                scriptPubKey=creditor_info.principal_change_addr.to_scriptPubKey(),  #noqa
            )
        )
        output_pubkeys.append(
            creditor_info.principal_change_addr.blinding_pubkey)

    collateral_change_amount = (
        debtor_info.collateral_amount - repayment_plan.collateral.amount
    )
    if collateral_change_amount > 0:
        tx.vout.append(
            CElementsMutableTxOut(
                nValue=CConfidentialValue(collateral_change_amount),
                nAsset=CConfidentialAsset(repayment_plan.collateral.asset),
                scriptPubKey=debtor_info.collateral_change_addr.to_scriptPubKey(),  # noqa
            )
        )
        output_pubkeys.append(
            debtor_info.collateral_change_addr.blinding_pubkey)

    input_descriptors = [
        BlindingInputDescriptor(
            asset=repayment_plan.collateral.asset,
            amount=debtor_info.collateral_amount,
            blinding_factor=debtor_info.value_blinding_factor,
            asset_blinding_factor=debtor_info.asset_blinding_factor,
        ),
        BlindingInputDescriptor(
            asset=repayment_plan.principal.asset,
            amount=creditor_info.principal_amount,
            blinding_factor=creditor_info.value_blinding_factor,
            asset_blinding_factor=creditor_info.asset_blinding_factor,
        ),
        fee_utxo_info.blinding_input_descriptor
    ]
    cprng_seed = hashlib.sha256(
        safe_derive(shared_blinding_xkey, SEED_CONTRACT_TX_PATH)
    ).digest()

    block_cprng = make_block_cprng(cprng_seed)

    random_consumed = 0

    def deterministic_random_generator(len: int) -> bytes:
        nonlocal random_consumed
        assert len == 32

        if random_consumed < 3 * RANDOM_BYTES_PER_UNIT_BLINDING:
            random_consumed += 32
            return block_cprng(len)

        # Random data for change outputs needs to be unpredictable
        return os.urandom(len)

    # At first, blind the clone of the transaction to
    # get the blinding factors that we need to create contract address
    blind_result = blind_tx_and_validate(
        tx.clone(), input_descriptors, output_pubkeys,
        deterministic_random_generator,
    )

    contract_input_descriptor = BlindingInputDescriptor(
        asset=repayment_plan.collateral.asset,
        amount=repayment_plan.collateral.amount,
        blinding_factor=blind_result.blinding_factors[0],
        asset_blinding_factor=blind_result.asset_blinding_factors[0],
    )

    generate_abl_contract_for_lateral_stage(
        repayment_plan.first_lateral_stage,
        shared_blinding_xkey,
        start_block_num,
        creditor_control_asset,
        debtor_control_asset,
        bitcoin_asset,
        contract_input_descriptor
    )

    start_vstage = repayment_plan.first_lateral_stage.vertical_stages[0]
    contract_addr = P2WSHCoinAddress.from_redeemScript(
        start_vstage.script_data.script
    )

    assert tx.vout[0].scriptPubKey == contract_dummy_addr.to_scriptPubKey()
    tx.vout[0].scriptPubKey = contract_addr.to_scriptPubKey()

    # Blind the transaction that has the contract address set
    block_cprng = make_block_cprng(cprng_seed)
    random_consumed = 0
    blind_tx_and_validate(
        tx, input_descriptors, output_pubkeys,
        deterministic_random_generator,
    )

    return tx, creditor_control_asset, debtor_control_asset


def return_debt_tx(
    vstage: VerticalProgressionStage,
    creditor_control_asset: CreditorAsset,
    debtor_control_asset: DebtorAsset,
    bitcoin_asset: BitcoinAsset,
    *,
    contract_tx: CElementsTransaction,
    debtor_control_tx: CElementsTransaction,
    fee_change_addr: CCoinConfidentialAddress,
    debtor_return_addr: CCoinConfidentialAddress,
    fee_amount: int,
    fee_utxo_info: BlindedInputInfo,
    debt_utxo_info: Optional[BlindedInputInfo] = None,
    is_full: bool = False,
) -> CElementsTransaction:
    """Send all debt early"""

    fee_cout = fee_utxo_info.outpoint
    fee_desc = fee_utxo_info.blinding_input_descriptor

    debtor_control_txout_index = find_explicit_asset_txout_index(
        debtor_control_tx, debtor_control_asset
    )

    inputs = [
        CTxIn(COutPoint(contract_tx.GetTxid(), CONTRACT_COLLATERAL_OUT_INDEX)),
        CTxIn(COutPoint(debtor_control_tx.GetTxid(),
                        debtor_control_txout_index)),
        CTxIn(COutPoint(fee_cout.hash, fee_cout.n)),
    ]

    descriptors = [fee_desc]

    # prepare the debt utxo
    if debt_utxo_info:
        inputs.append(CTxIn(debt_utxo_info.outpoint))
        descriptors.append(debt_utxo_info.blinding_input_descriptor)
        debt_in_btc = 0
    else:
        # the debt will be paid from fee utxo
        debt_in_btc = (
            vstage.full_repayment_amount
            if is_full else vstage.regular_repayment_amount
        )

    # prepare the fee utxo
    fee_utxo_amount = Amount(fee_desc.amount)
    fee_change_amount = fee_utxo_amount - fee_amount - debt_in_btc
    assert fee_change_amount > 0

    def build_tx_func() -> ContractMutableTransaction:
        if is_full:
            return build_full_repayment_transaction(
                vstage,
                creditor_control_asset,
                debtor_control_asset,
                bitcoin_asset,
                fee_change_addr=fee_change_addr,
                return_addr=debtor_return_addr,
                inputs=inputs,
                fee_change_amount=fee_change_amount,
                fee_amount=fee_amount,
                descriptors=descriptors)
        else:
            return build_partial_repayment_transaction(
                vstage,
                creditor_control_asset,
                debtor_control_asset,
                bitcoin_asset,
                fee_change_addr=fee_change_addr,
                return_addr=debtor_return_addr,
                inputs=inputs,
                fee_change_amount=fee_change_amount,
                fee_amount=fee_amount,
                descriptors=descriptors)

    tx = build_tx_func()

    # sign the contract input
    checked_outs_data = tx.checked_outs_data
    offset = vstage.script_data.checked_outs_hashes.index(
        hashlib.sha256(checked_outs_data).digest()
    )
    assert offset % 32 == 0
    sign_for_covenant(
        tx,
        0,
        [offset // 32, 0],
        checked_outs_data,
        tx.other_outs_data,
        contract_tx.vout[CONTRACT_COLLATERAL_OUT_INDEX].nValue,
        vstage.script_data.script,
    )
    return tx


def spend_via_control_asset_tx(
    *,
    amount: int,
    src_tx: CElementsTransaction,
    src_txout_index: int,
    src_input_descriptor: BlindingInputDescriptor,
    control_asset: CAsset,
    control_tx: CElementsTransaction,
    fee_utxo_info: BlindedInputInfo,
    fee_amount: int,
    dst_addr: CCoinConfidentialAddress,
    fee_change_addr: CCoinConfidentialAddress,
    control_asset_return_addr: Optional[CCoinAddress] = None,
    is_final: bool = False,
    bitcoin_asset: BitcoinAsset
) -> CElementsTransaction:
    """Spend the utxo using control asset"""
    assert amount > 0
    assert isinstance(dst_addr, CCoinConfidentialAddress)

    fee_outpoint = fee_utxo_info.outpoint
    fee_desc = fee_utxo_info.blinding_input_descriptor
    fee_utxo_amount = Amount(fee_desc.amount)
    fee_change_amount = fee_utxo_amount - fee_amount
    assert fee_change_amount > 0

    if is_final:
        assert control_asset_return_addr is None
        control_asset_scriptpubkey = CScript([OP_RETURN])
    else:
        assert control_asset_return_addr is not None
        control_asset_scriptpubkey = (
            control_asset_return_addr.to_scriptPubKey()
        )

    control_txout_index = find_explicit_asset_txout_index(
        control_tx, control_asset
    )

    tx = CElementsMutableTransaction(
        vin=[
            CTxIn(COutPoint(src_tx.GetTxid(), src_txout_index)),
            CTxIn(COutPoint(control_tx.GetTxid(), control_txout_index)),
            CTxIn(fee_outpoint)
        ],
        vout=[
            CElementsTxOut(
                nValue=CConfidentialValue(1),
                nAsset=CConfidentialAsset(control_asset),
                scriptPubKey=control_asset_scriptpubkey,
            ),
            CElementsTxOut(
                nValue=CConfidentialValue(amount),
                nAsset=CConfidentialAsset(src_input_descriptor.asset),
                scriptPubKey=dst_addr.to_scriptPubKey(),
            ),
            CElementsTxOut(
                nValue=CConfidentialValue(fee_change_amount),
                nAsset=CConfidentialAsset(bitcoin_asset),
                scriptPubKey=fee_change_addr.to_scriptPubKey(),
            ),
            CElementsTxOut(
                nValue=CConfidentialValue(fee_amount),
                nAsset=CConfidentialAsset(bitcoin_asset),
            ),
        ],
    )

    output_pubkeys = [
        CPubKey(),
        dst_addr.blinding_pubkey,
        fee_change_addr.blinding_pubkey,
    ]

    input_descriptors = [
        src_input_descriptor,
        BlindingInputDescriptor(
            asset=control_asset,
            amount=1,
            blinding_factor=Uint256(),
            asset_blinding_factor=Uint256(),
        ),
        fee_desc,
    ]

    blind_tx_and_validate(tx, input_descriptors, output_pubkeys)

    b_io = BytesIO()
    tx.vout[0].nAsset.stream_serialize(b_io)
    tx.vout[0].nValue.stream_serialize(b_io)
    tx.vout[0].nNonce.stream_serialize(b_io)
    checked_outs_data = bytes(b_io.getbuffer())
    other_outs_data = tx.vout[0].serialize()[
        len(checked_outs_data):
    ] + b"".join(txout.serialize() for txout in tx.vout[1:])

    sign_for_covenant(
        tx,
        0,
        [],
        None,
        other_outs_data,
        src_tx.vout[src_txout_index].nValue,
        get_control_script(control_asset),
    )
    return tx


def create_mutual_spend_transaction(
    vstage: VerticalProgressionStage,
    creditor_control_asset: CreditorAsset,
    debtor_control_asset: DebtorAsset,
    contract_tx: CElementsTransaction,
    *,
    principal_to_creditor_amount: int = 0,
    principal_to_creditor_addr: Optional[CCoinConfidentialAddress] = None,
    collateral_to_debtor_amount: int = 0,
    collateral_to_debtor_addr: Optional[CCoinConfidentialAddress] = None,
    collateral_to_creditor_amount: int = 0,
    collateral_to_creditor_addr: Optional[CCoinConfidentialAddress] = None,
) -> Tuple[CElementsMutableTransaction, List[CPubKey]]:
    """Create the transaction template for mutual contract close"""

    tx = CElementsMutableTransaction(
        vin=[
            CTxIn(
                COutPoint(hash=contract_tx.GetTxid(),
                          n=CONTRACT_COLLATERAL_OUT_INDEX)
            ),
        ],
        vout=[
            CElementsTxOut(
                nValue=CConfidentialValue(1),
                nAsset=CConfidentialAsset(asset),
                scriptPubKey=CScript([OP_RETURN]),
            )
            for asset in (creditor_control_asset, debtor_control_asset)
        ],
    )

    output_blind_pubkeys: List[CPubKey] = [CPubKey(), CPubKey()]

    amounts_addrs_assets = ((principal_to_creditor_amount,
                             principal_to_creditor_addr,
                             vstage.plan.principal.asset,
                             "principal_to_creditor"),
                            (collateral_to_debtor_amount,
                             collateral_to_debtor_addr,
                             vstage.plan.collateral.asset,
                             "collateral_to_debtor"),
                            (collateral_to_creditor_amount,
                             collateral_to_creditor_addr,
                             vstage.plan.collateral.asset,
                             "collateral_to_creditor"))

    for amount, addr, asset, aadesc in amounts_addrs_assets:
        if amount > 0:
            assert addr is not None
            tx.vout.append(
                CElementsMutableTxOut(
                    nValue=CConfidentialValue(amount),
                    nAsset=CConfidentialAsset(asset),
                    scriptPubKey=addr.to_scriptPubKey(),
                )
            )
            tx.wit.vtxoutwit.append(CElementsMutableTxOutWitness())
            output_blind_pubkeys.append(addr.blinding_pubkey)
        else:
            assert amount == 0
            assert addr is None

    # TODO: use psbt in the future
    return tx, output_blind_pubkeys


def grab_collateral_tx(
    vstage: VerticalProgressionStage,
    creditor_control_asset: CreditorAsset,
    debtor_control_asset: DebtorAsset,
    bitcoin_asset: BitcoinAsset,
    *,
    fee_utxo_info: BlindedInputInfo,
    start_block_num: int,
    fee_amount: int,
    contract_tx: CElementsTransaction,
    creditor_control_tx: CElementsTransaction,
    fee_change_addr: CCoinConfidentialAddress,
    grab_dst_addr: CCoinConfidentialAddress,
) -> CElementsTransaction:
    """Send the grab transaction"""

    lstage = vstage.parent_lateral_stage

    assert (
        vstage.index_m == len(lstage.vertical_stages) - 1
    ), "stage is expected to be last stage in the plan"

    creditor_control_txout_index = find_explicit_asset_txout_index(
        creditor_control_tx, creditor_control_asset
    )

    fee_outpoint = fee_utxo_info.outpoint
    fee_desc = fee_utxo_info.blinding_input_descriptor
    fee_utxo_amount = Amount(fee_desc.amount)
    fee_change_amount = fee_utxo_amount - fee_amount
    assert fee_change_amount > 0

    final_timeout = (
        (lstage.level_n + len(lstage.vertical_stages))
        * lstage.plan.num_blocks_in_period
    )

    inputs = (
        CTxIn(COutPoint(contract_tx.GetTxid(),
                        CONTRACT_COLLATERAL_OUT_INDEX),
              nSequence=0xFFFFFFFE),  # enable nLockTime check
        CTxIn(COutPoint(creditor_control_tx.GetTxid(),
                        creditor_control_txout_index)),
        CTxIn(fee_outpoint)
    )
    descriptors = (fee_desc,)

    tx = build_grab_transaction(
        vstage,
        creditor_control_asset,
        debtor_control_asset,
        bitcoin_asset,
        fee_change_addr=fee_change_addr,
        creditor_collateral_grab_addr=grab_dst_addr,
        inputs=inputs,
        fee_change_amount=fee_change_amount,
        fee_amount=fee_amount,
        descriptors=descriptors,
        nLockTime=start_block_num + final_timeout - 1,
    )

    # sign the contract input
    sign_for_covenant(
        tx,
        0,
        [1],
        tx.checked_outs_data,
        tx.other_outs_data,
        contract_tx.vout[CONTRACT_COLLATERAL_OUT_INDEX].nValue,
        vstage.script_data.script,
    )

    return tx


def revoke_debt_return_window_tx(
    vstage: VerticalProgressionStage,
    creditor_control_asset: CreditorAsset,
    bitcoin_asset: BitcoinAsset,
    *,
    contract_tx: CElementsTransaction,
    creditor_control_tx: CElementsTransaction,
    start_block_num: int,
    fee_utxo_info: BlindedInputInfo,
    fee_amount: int,
    fee_change_addr: CCoinConfidentialAddress,
    creditor_ctrl_return_addr: CCoinAddress,
) -> CElementsTransaction:
    """Send the transaction that make the transition to next stage"""
    lstage = vstage.parent_lateral_stage
    assert vstage.index_m < len(lstage.vertical_stages) - 1
    creditor_control_txout_index = find_explicit_asset_txout_index(
        creditor_control_tx, creditor_control_asset
    )

    fee_outpoint = fee_utxo_info.outpoint
    fee_desc = fee_utxo_info.blinding_input_descriptor

    fee_utxo_amount = Amount(fee_desc.amount)
    fee_change_amount = fee_utxo_amount - fee_amount
    assert fee_change_amount > 0

    inputs = (
        CTxIn(COutPoint(contract_tx.GetTxid(), CONTRACT_COLLATERAL_OUT_INDEX),
              nSequence=0xFFFFFFFE),  # enable nLockTime check
        CTxIn(COutPoint(creditor_control_tx.GetTxid(),
                        creditor_control_txout_index)),
        CTxIn(fee_outpoint)
    )
    descriptors = (fee_desc,)

    timeout_blocks = (
        lstage.level_n + vstage.index_m + 1
    ) * lstage.plan.num_blocks_in_period

    tx = build_revocation_transaction(
        vstage,
        creditor_control_asset,
        bitcoin_asset,
        fee_change_addr=fee_change_addr,
        creditor_ctrl_return_addr=creditor_ctrl_return_addr,
        inputs=inputs,
        fee_change_amount=fee_change_amount,
        fee_amount=fee_amount,
        descriptors=descriptors,
        nLockTime=start_block_num + timeout_blocks - 1,
    )

    sign_for_covenant(
        tx,
        0,
        [1],
        tx.checked_outs_data,
        tx.other_outs_data,
        contract_tx.vout[CONTRACT_COLLATERAL_OUT_INDEX].nValue,
        vstage.script_data.script,
    )

    return tx
