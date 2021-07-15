# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from typing import Iterable

from bitcointx.core import CTxIn, Uint256
from bitcointx.core.key import CPubKey
from bitcointx.core.script import OP_RETURN, CScript
from bitcointx.wallet import CCoinAddress, P2WSHCoinAddress
from elementstx.core import (
    CElementsTxOut,
    BlindingInputDescriptor,
    CConfidentialAsset,
    CConfidentialValue,
)
from elementstx.wallet import CCoinConfidentialAddress

from .constants import (
    BLIND_PUB_COLLATERAL_GRAB_TX_PATH,
    BLIND_PUB_COLLATERAL_RETURN_DEBT_TX_PATH,
    BLIND_PUB_COLLATERAL_RETURN_TX_PATH,
    BLIND_PUB_COLLATERAL_REVOKE_TX_PATH,
    BLIND_PUB_PAYMENT_RETURN_DEBT_TX_PATH,
    SEED_GRAB_TX_PATH,
    SEED_RETURN_DEBT_TX_PATH,
    SEED_RETURN_TX_PATH,
    SEED_REVOKE_TX_PATH,
)
from .scripts import get_control_script
from .types import (
    ContractMutableTransaction, VerticalProgressionStage,
    CreditorAsset, DebtorAsset, BitcoinAsset
)
from .utils import blind_tx_and_validate, safe_derive


def build_partial_repayment_transaction(
    vstage: VerticalProgressionStage,
    creditor_control_asset: CreditorAsset,
    debtor_control_asset: DebtorAsset,
    bitcoin_asset: BitcoinAsset,
    *,
    fee_change_addr: CCoinConfidentialAddress,
    return_addr: CCoinAddress,
    inputs: Iterable[CTxIn],
    fee_change_amount: int,
    fee_amount: int,
    descriptors: Iterable[BlindingInputDescriptor],
) -> ContractMutableTransaction:

    assert vstage.next_lateral_stage is not None
    assert len(vstage.next_lateral_stage.vertical_stages) > 0

    creditor_control_scriptpubkey = P2WSHCoinAddress.from_redeemScript(
        get_control_script(creditor_control_asset)
    ).to_scriptPubKey()

    branch_dst_addr = P2WSHCoinAddress.from_redeemScript(
        vstage.next_lateral_stage.vertical_stages[0].script_data.script
    )

    tx = ContractMutableTransaction(
        vin=list(inputs),
        vout=[
            CElementsTxOut(
                # Note that we do not reduce collateral with partial
                # repayments. This is due to limitations of
                # the covenant script, we can only commit to limited number
                # of blinded outputs.
                nValue=CConfidentialValue(vstage.plan.collateral.amount),
                nAsset=CConfidentialAsset(vstage.plan.collateral.asset),
                scriptPubKey=branch_dst_addr.to_scriptPubKey(),
            ),
            CElementsTxOut(
                nValue=CConfidentialValue(vstage.regular_repayment_amount),
                nAsset=CConfidentialAsset(vstage.plan.principal.asset),
                scriptPubKey=creditor_control_scriptpubkey,
            ),
            CElementsTxOut(
                nValue=CConfidentialValue(1),
                nAsset=CConfidentialAsset(debtor_control_asset),
                scriptPubKey=return_addr.to_scriptPubKey(),
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
        safe_derive(
            vstage.blinding_data.blinding_xkey,
            BLIND_PUB_COLLATERAL_RETURN_DEBT_TX_PATH
        ).pub,
        safe_derive(
            vstage.blinding_data.blinding_xkey,
            BLIND_PUB_PAYMENT_RETURN_DEBT_TX_PATH
        ).pub,
        CPubKey(),
        fee_change_addr.blinding_pubkey,
    ]
    input_descriptors = [
        vstage.blinding_data.contract_input_descriptor,
        BlindingInputDescriptor(
            asset=debtor_control_asset,
            amount=1,
            blinding_factor=Uint256(),
            asset_blinding_factor=Uint256(),
        ),
        *descriptors,
    ]
    deterministic_random_generator = (
        vstage.build_deterministic_random_generator(
            SEED_RETURN_DEBT_TX_PATH,
            contract_entropy=vstage.branch_contract_entropy,
            num_special_blindings=2
        )
    )

    assert (
        sum(out.nValue.to_amount() for out in tx.vout)
        == sum(idesc.amount for idesc in input_descriptors)
    )

    blind_tx_and_validate(
        tx, input_descriptors, output_pubkeys, deterministic_random_generator
    )
    return tx


def build_full_repayment_transaction(
    vstage: VerticalProgressionStage,
    creditor_control_asset: CreditorAsset,
    debtor_control_asset: DebtorAsset,
    bitcoin_asset: BitcoinAsset,
    *,
    fee_change_addr: CCoinConfidentialAddress,
    return_addr: CCoinConfidentialAddress,
    inputs: Iterable[CTxIn],
    fee_change_amount: int,
    fee_amount: int,
    descriptors: Iterable[BlindingInputDescriptor],
) -> ContractMutableTransaction:
    creditor_control_scriptpubkey = P2WSHCoinAddress.from_redeemScript(
        get_control_script(creditor_control_asset)
    ).to_scriptPubKey()

    plan = vstage.parent_lateral_stage.plan

    tx = ContractMutableTransaction(
        vin=list(inputs),
        vout=[
            CElementsTxOut(
                nValue=CConfidentialValue(vstage.full_repayment_amount),
                nAsset=CConfidentialAsset(plan.principal.asset),
                scriptPubKey=creditor_control_scriptpubkey,
            ),
            CElementsTxOut(
                nValue=CConfidentialValue(1),
                nAsset=CConfidentialAsset(debtor_control_asset),
                # debtor_control_asset is no longer needed,
                # nothing to control with it because debt is returned
                scriptPubKey=CScript([OP_RETURN]),
            ),
            CElementsTxOut(
                nValue=CConfidentialValue(
                    vstage.blinding_data.contract_input_descriptor.amount
                ),
                nAsset=CConfidentialAsset(
                    vstage.blinding_data.contract_input_descriptor.asset
                ),
                scriptPubKey=return_addr.to_scriptPubKey(),
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
        safe_derive(
            vstage.blinding_data.blinding_xkey,
            BLIND_PUB_COLLATERAL_RETURN_TX_PATH
        ).pub,
        CPubKey(),
        return_addr.blinding_pubkey,
        fee_change_addr.blinding_pubkey,
    ]

    input_descriptors = [
        vstage.blinding_data.contract_input_descriptor,
        BlindingInputDescriptor(
            asset=debtor_control_asset,
            amount=1,
            blinding_factor=Uint256(),
            asset_blinding_factor=Uint256(),
        ),
        *descriptors,
    ]

    # special blindings include principal output to the creditor
    # and collateral output to the debtor
    deterministic_random_generator = (
        vstage.build_deterministic_random_generator(
            SEED_RETURN_TX_PATH, num_special_blindings=2)
    )

    blind_tx_and_validate(
        tx, input_descriptors, output_pubkeys, deterministic_random_generator
    )
    return tx


def build_revocation_transaction(
    vstage: VerticalProgressionStage,
    creditor_control_asset: CreditorAsset,
    bitcoin_asset: BitcoinAsset,
    *,
    fee_change_addr: CCoinConfidentialAddress,
    creditor_ctrl_return_addr: CCoinAddress,
    inputs: Iterable[CTxIn],
    fee_change_amount: int,
    fee_amount: int,
    descriptors: Iterable[BlindingInputDescriptor],
    nLockTime: int,
) -> ContractMutableTransaction:
    next_vstage = vstage.parent_lateral_stage.vertical_stages[
        vstage.index_m + 1
    ]
    next_vstage_spk = P2WSHCoinAddress.from_redeemScript(
        next_vstage.script_data.script
    ).to_scriptPubKey()

    tx = ContractMutableTransaction(
        vin=list(inputs),
        vout=[
            CElementsTxOut(
                nValue=CConfidentialValue(
                    vstage.blinding_data.contract_input_descriptor.amount),
                nAsset=CConfidentialAsset(
                    vstage.blinding_data.contract_input_descriptor.asset),
                scriptPubKey=next_vstage_spk,
            ),
            CElementsTxOut(
                nValue=CConfidentialValue(1),
                nAsset=CConfidentialAsset(creditor_control_asset),
                scriptPubKey=creditor_ctrl_return_addr.to_scriptPubKey(),
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
        nLockTime=nLockTime,
    )

    output_pubkeys = [
        safe_derive(
            vstage.blinding_data.blinding_xkey,
            BLIND_PUB_COLLATERAL_REVOKE_TX_PATH
        ).pub,
        CPubKey(),
        fee_change_addr.blinding_pubkey,
    ]

    cid = next_vstage.blinding_data.contract_input_descriptor
    next_stage_contract_entropy = (
        cid.blinding_factor.data + cid.asset_blinding_factor.data
    )
    input_descriptors = [
        vstage.blinding_data.contract_input_descriptor,
        BlindingInputDescriptor(
            asset=creditor_control_asset,
            amount=1,
            blinding_factor=Uint256(),
            asset_blinding_factor=Uint256(),
        ),
        *descriptors,
    ]

    deterministic_random_generator = (
        vstage.build_deterministic_random_generator(
            SEED_REVOKE_TX_PATH,
            contract_entropy=next_stage_contract_entropy,
            num_special_blindings=1
        )
    )

    blind_result = blind_tx_and_validate(
        tx, input_descriptors, output_pubkeys, deterministic_random_generator
    )

    assert (
        blind_result.blinding_factors[0].data
        == next_stage_contract_entropy[:32]
    ), "Resulting blinding factor does not match contract entropy"

    assert (
        blind_result.asset_blinding_factors[0].data
        == next_stage_contract_entropy[32:]
    ), "Resulting asset blinding factor does not match contract entropy"
    return tx


def build_grab_transaction(
    vstage: VerticalProgressionStage,
    creditor_control_asset: CreditorAsset,
    debtor_control_asset: DebtorAsset,
    bitcoin_asset: BitcoinAsset,
    *,
    fee_change_addr: CCoinConfidentialAddress,
    creditor_collateral_grab_addr: CCoinConfidentialAddress,
    inputs: Iterable[CTxIn],
    fee_change_amount: int,
    fee_amount: int,
    descriptors: Iterable[BlindingInputDescriptor],
    nLockTime: int,
) -> ContractMutableTransaction:

    assert fee_change_amount > 0
    debtor_control_scriptpubkey = P2WSHCoinAddress.from_redeemScript(
        get_control_script(debtor_control_asset)
    ).to_scriptPubKey()

    collateral_asset = vstage.plan.collateral.asset

    collateral_change_amount = vstage.plan.C - vstage.amount_C_forfeited

    assert collateral_change_amount >= 0

    if collateral_change_amount > 0:
        debtor_vout_lst = [
            CElementsTxOut(
                nValue=CConfidentialValue(collateral_change_amount),
                nAsset=CConfidentialAsset(collateral_asset),
                scriptPubKey=debtor_control_scriptpubkey,
            ),
        ]
        debtor_pubkeys_lst = [
            safe_derive(
                vstage.blinding_data.blinding_xkey,
                BLIND_PUB_COLLATERAL_GRAB_TX_PATH
            ).pub,
        ]
    else:
        # the creditor takes the all, the debtor will give nothing
        debtor_vout_lst = []
        debtor_pubkeys_lst = []

    tx = ContractMutableTransaction(
        vin=list(inputs),
        vout=debtor_vout_lst + [
            CElementsTxOut(
                nValue=CConfidentialValue(1),
                nAsset=CConfidentialAsset(creditor_control_asset),
                scriptPubKey=CScript([OP_RETURN]),
            ),
            CElementsTxOut(
                nValue=CConfidentialValue(vstage.amount_C_forfeited),
                nAsset=CConfidentialAsset(collateral_asset),
                scriptPubKey=creditor_collateral_grab_addr.to_scriptPubKey(),
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
        nLockTime=nLockTime,
    )

    output_pubkeys = debtor_pubkeys_lst + [
        CPubKey(),
        creditor_collateral_grab_addr.blinding_pubkey,
        fee_change_addr.blinding_pubkey,
    ]

    input_descriptors = [
        vstage.blinding_data.contract_input_descriptor,
        BlindingInputDescriptor(
            asset=creditor_control_asset,
            amount=1,
            blinding_factor=Uint256(),
            asset_blinding_factor=Uint256(),
        ),
        *descriptors,
    ]

    # special blindings include collateral change output and
    # collateral forfeiture output
    deterministic_random_generator = (
        vstage.build_deterministic_random_generator(
            SEED_GRAB_TX_PATH,
            num_special_blindings=2 if collateral_change_amount > 0 else 1,
        )
    )

    blind_tx_and_validate(
        tx, input_descriptors, output_pubkeys, deterministic_random_generator
    )
    return tx
