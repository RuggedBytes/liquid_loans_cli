# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import hashlib
import os
from typing import Optional, Tuple, Generator, List

from bitcointx.core import COutPoint, CTxIn, b2x, Uint256
from bitcointx.core.script import (
    OP_CHECKLOCKTIMEVERIFY,
    OP_DROP,
    OP_ELSE,
    OP_ENDIF,
    OP_IF,
    OP_RETURN,
    CScript,
    ScriptElement_Type
)
from bitcointx.wallet import CCoinExtKey, CCoinKey, P2WPKHCoinAddress
from elementstx.core import (
    BlindingInputDescriptor,
    CConfidentialAsset,
    CConfidentialValue,
    CElementsTxOut
)
from elementstx.wallet import CCoinConfidentialAddress

from .builders import (
    build_grab_transaction,
    build_partial_repayment_transaction,
    build_full_repayment_transaction,
    build_revocation_transaction,
)
from .constants import (
    STAGE_BLINDING_ASSET_FACTOR_PATH,
    STAGE_BLINDING_FACTOR_PATH,
    STAGE_NEXT_LEVEL_PATH
)
from .scripts import (
    covenant_outputs_check_ops,
    covenant_outputs_hash_check_ops,
    covenant_outputs_hash_lookup_ops,
    get_control_asset_out_data_sans_scriptpubkey,
)
from .types import (
    CreditorAsset, DebtorAsset, BitcoinAsset,
    LateralProgressionStage, VerticalProgressionStage,
    VerticalProgressionStageBlindingData, VerticalProgressionStageScriptData
)
from .utils import safe_derive


def get_dummy_addr() -> P2WPKHCoinAddress:
    return P2WPKHCoinAddress.from_pubkey(
        CCoinKey.from_secret_bytes(os.urandom(32)).pub
    )


def get_dummy_confidential_addr() -> CCoinConfidentialAddress:
    return CCoinConfidentialAddress.from_unconfidential(
        get_dummy_addr(), CCoinKey.from_secret_bytes(os.urandom(32)).pub
    )


def dummy_inputs_generator(num_inputs: int) -> Generator[CTxIn, None, None]:
    for _ in range(num_inputs):
        yield CTxIn(COutPoint())


def get_hash_of_collateral_forfeiture_checked_outs(
    last_vstage: VerticalProgressionStage,
    creditor_control_asset: CreditorAsset,
    debtor_control_asset: DebtorAsset,
    bitcoin_asset: BitcoinAsset
) -> bytes:

    dummy_fee_change_addr = get_dummy_confidential_addr()
    dummy_inputs = dummy_inputs_generator(3)
    dummy_grub_addr = get_dummy_confidential_addr()
    dummy_change_amount = 1
    dummy_fee_amount = 1
    dummy_nLockTime = 0
    dummy_descriptors = (
        BlindingInputDescriptor(
            asset=bitcoin_asset,
            amount=dummy_change_amount + dummy_fee_amount,
            blinding_factor=Uint256(os.urandom(32)),
            asset_blinding_factor=Uint256(os.urandom(32)),
        ),
    )

    tx = build_grab_transaction(
        last_vstage,
        creditor_control_asset,
        debtor_control_asset,
        bitcoin_asset,
        fee_change_addr=dummy_fee_change_addr,
        creditor_collateral_grab_addr=dummy_grub_addr,
        inputs=dummy_inputs,
        fee_change_amount=dummy_change_amount,
        fee_amount=dummy_fee_amount,
        descriptors=dummy_descriptors,
        nLockTime=dummy_nLockTime,
    )
    return hashlib.sha256(tx.checked_outs_data).digest()


def get_mutual_close_tx_checked_outs(
    creditor_control_asset: CreditorAsset,
    debtor_control_asset: DebtorAsset,
) -> bytes:
    # In a mutual close, both creditor and debtor control assets are burned,
    # and this means that creditor and debtor has to supply their signed
    # inputs for their respective assets. Revocation asset is burned, too
    # so that no stray utxo is left afterwards.
    #
    # If the parties want to rollover the contract, they can issue new
    # assets and use other outputs for these new assets.
    #
    # We could allow the assets to be rolled over, too, but then we could not
    # use just a hash of continuous serialized outputs data, and would need
    # to use three separate pieces of data for each output, concatenate them
    # with respective scriptpubkeys, etc. We will need to have an extra
    # IF case in the main script. With just one hash, we do not need extra IF,
    # as this hash can just be added to the hashes for other contract cases.
    txouts = [
        CElementsTxOut(
            nValue=CConfidentialValue(1),
            nAsset=CConfidentialAsset(asset),
            scriptPubKey=CScript([OP_RETURN]),
        )
        for asset in (creditor_control_asset, debtor_control_asset)
    ]

    return b"".join(txo.serialize() for txo in txouts)


def get_full_repayment_checked_outs_data(
    vstage: VerticalProgressionStage,
    creditor_control_asset: CreditorAsset,
    debtor_control_asset: DebtorAsset,
    bitcoin_asset: BitcoinAsset,
) -> bytes:
    dummy_fee_change_addr = get_dummy_confidential_addr()
    dummy_inputs = dummy_inputs_generator(4)
    dummy_debtor_return_addr = get_dummy_confidential_addr()
    dummy_change_amount = 1
    dummy_fee_amount = 1
    dummy_descriptors = (
        BlindingInputDescriptor(
            asset=bitcoin_asset,
            amount=dummy_change_amount + dummy_fee_amount,
            blinding_factor=Uint256(os.urandom(32)),
            asset_blinding_factor=Uint256(os.urandom(32)),
        ),
        BlindingInputDescriptor(
            asset=vstage.plan.principal.asset,
            amount=vstage.full_repayment_amount,
            blinding_factor=Uint256(os.urandom(32)),
            asset_blinding_factor=Uint256(os.urandom(32)),
        ),
    )
    tx = build_full_repayment_transaction(
        vstage,
        creditor_control_asset,
        debtor_control_asset,
        bitcoin_asset,
        fee_change_addr=dummy_fee_change_addr,
        return_addr=dummy_debtor_return_addr,
        inputs=dummy_inputs,
        fee_change_amount=dummy_change_amount,
        fee_amount=dummy_fee_amount,
        descriptors=dummy_descriptors,
    )
    return tx.checked_outs_data


def get_partial_repayment_checked_outs_data(
    vstage: VerticalProgressionStage,
    creditor_control_asset: CreditorAsset,
    debtor_control_asset: DebtorAsset,
    bitcoin_asset: BitcoinAsset,
) -> Optional[bytes]:

    if vstage.next_lateral_stage is None:
        return None

    dummy_fee_change_addr = get_dummy_confidential_addr()
    dummy_inputs = dummy_inputs_generator(4)
    dummy_ctrl_return_addr = get_dummy_addr()
    dummy_change_amount = 1
    dummy_fee_amount = 1
    dummy_descriptors = (
        BlindingInputDescriptor(
            asset=bitcoin_asset,
            amount=dummy_change_amount + dummy_fee_amount,
            blinding_factor=Uint256(os.urandom(32)),
            asset_blinding_factor=Uint256(os.urandom(32)),
        ),
        BlindingInputDescriptor(
            asset=vstage.plan.principal.asset,
            amount=vstage.regular_repayment_amount,
            blinding_factor=Uint256(os.urandom(32)),
            asset_blinding_factor=Uint256(os.urandom(32)),
        ),
    )
    tx = build_partial_repayment_transaction(
        vstage,
        creditor_control_asset,
        debtor_control_asset,
        bitcoin_asset,
        fee_change_addr=dummy_fee_change_addr,
        return_addr=dummy_ctrl_return_addr,
        inputs=dummy_inputs,
        fee_change_amount=dummy_change_amount,
        fee_amount=dummy_fee_amount,
        descriptors=dummy_descriptors,
    )
    return tx.checked_outs_data


def get_revocation_tx_checked_outs_data(
    vstage: VerticalProgressionStage,
    creditor_control_asset: CreditorAsset,
    bitcoin_asset: BitcoinAsset,
) -> Optional[bytes]:
    lstage = vstage.parent_lateral_stage
    if vstage.index_m >= len(lstage.vertical_stages) - 1:
        return None

    dummy_fee_change_addr = get_dummy_confidential_addr()
    dummy_inputs = dummy_inputs_generator(3)
    dummy_ctrl_return_addr = get_dummy_addr()
    dummy_change_amount = 1
    dummy_fee_amount = 1
    dummy_nLockTime = 0
    dummy_descriptors = (
        BlindingInputDescriptor(
            asset=bitcoin_asset,
            amount=dummy_change_amount + dummy_fee_amount,
            blinding_factor=Uint256(os.urandom(32)),
            asset_blinding_factor=Uint256(os.urandom(32)),
        ),
    )
    tx = build_revocation_transaction(
        vstage,
        creditor_control_asset,
        bitcoin_asset,
        fee_change_addr=dummy_fee_change_addr,
        creditor_ctrl_return_addr=dummy_ctrl_return_addr,
        inputs=dummy_inputs,
        fee_change_amount=dummy_change_amount,
        fee_amount=dummy_fee_amount,
        descriptors=dummy_descriptors,
        nLockTime=dummy_nLockTime,
    )
    return tx.checked_outs_data


def generate_script_and_checked_outs_hashes(
    vstage: VerticalProgressionStage,
    creditor_control_asset: CreditorAsset,
    debtor_control_asset: DebtorAsset,
    start_block_num: int,
    *,
    full_repayment_checked_outs_data: bytes,
    revoc_checked_outs_data: Optional[bytes],
    partial_repayment_checked_outs_data: Optional[bytes],
    hash_of_collateral_grab_outputs_data: bytes,
) -> Tuple[CScript, bytes]:
    assert start_block_num > 0
    mutual_close_checked_data_hash = hashlib.sha256(
        get_mutual_close_tx_checked_outs(
            creditor_control_asset, debtor_control_asset
        )
    ).digest()

    def get_creditor_outs_data_hash() -> bytes:
        if revoc_checked_outs_data is None:
            return hash_of_collateral_grab_outputs_data

        revoc_data_check_part = get_control_asset_out_data_sans_scriptpubkey(
            creditor_control_asset
        )
        assert revoc_checked_outs_data.endswith(revoc_data_check_part), (
            b2x(revoc_checked_outs_data),
            b2x(revoc_data_check_part),
        )

        return hashlib.sha256(revoc_checked_outs_data).digest()

    def get_debtor_outs_data_hash_block(
        vstage: VerticalProgressionStage
    ) -> bytes:
        stage_data_check_part = CElementsTxOut(
            nValue=CConfidentialValue(1),
            nAsset=CConfidentialAsset(debtor_control_asset),
            scriptPubKey=CScript([OP_RETURN]),
        ).serialize()
        # 99 is the size of the locked portion of the collateral-return output
        assert full_repayment_checked_outs_data[:-99].endswith(stage_data_check_part), ( # noqa
            b2x(full_repayment_checked_outs_data),
            b2x(stage_data_check_part),
        )
        hash_stage = hashlib.sha256(full_repayment_checked_outs_data).digest()
        if vstage.next_lateral_stage:
            branch_data_check_part = (
                get_control_asset_out_data_sans_scriptpubkey(
                    debtor_control_asset
                )
            )
            assert partial_repayment_checked_outs_data is not None
            assert partial_repayment_checked_outs_data.endswith(branch_data_check_part), (  # noqa
                b2x(partial_repayment_checked_outs_data),
                b2x(branch_data_check_part),
            )
            hash_branch = hashlib.sha256(
                partial_repayment_checked_outs_data
            ).digest()

            return hash_stage + hash_branch

        return hash_stage

    timeout = (
        vstage.parent_lateral_stage.level_n + vstage.index_m + 1
    ) * vstage.plan.num_blocks_in_period

    checked_outs_hashes = (
        get_debtor_outs_data_hash_block(vstage)
        + mutual_close_checked_data_hash
    )

    script_ops: List[ScriptElement_Type] = [
        OP_IF,
        # -1 because 1 confirmations of a tx means it is in the same block
        # it is mined in
        start_block_num + timeout - 1,
        OP_CHECKLOCKTIMEVERIFY,
        OP_DROP,
        get_creditor_outs_data_hash(),
        OP_ELSE,
        checked_outs_hashes,
    ]

    script_ops += covenant_outputs_hash_lookup_ops
    script_ops += [OP_ENDIF]
    script_ops += covenant_outputs_hash_check_ops
    script_ops += covenant_outputs_check_ops

    return CScript(script_ops), checked_outs_hashes


def generate_abl_contract_for_lateral_stage(
    lateral_stage: LateralProgressionStage,
    parent_blinding_xkey: CCoinExtKey,
    start_block_num: int,
    creditor_control_asset: CreditorAsset,
    debtor_control_asset: DebtorAsset,
    bitcoin_asset: BitcoinAsset,
    first_stage_input_descriptor: Optional[BlindingInputDescriptor] = None
) -> int:
    """
    Generate the main contract code and accompanying data,
    and store all the info in vertical stage objects
    """

    assert start_block_num > 0

    lstage = lateral_stage
    plan = lstage.plan

    lstage_blinding_xkey = safe_derive(
        parent_blinding_xkey, STAGE_NEXT_LEVEL_PATH
    )

    # Need blinding factors and input descriptors ready
    # before we can generate the scripts
    for vstage in lstage.vertical_stages:

        blinding_xkey = safe_derive(
            lstage_blinding_xkey, f'{vstage.index_m}h')

        blinding_factor = hashlib.sha256(
            safe_derive(blinding_xkey, STAGE_BLINDING_FACTOR_PATH)
        ).digest()

        asset_blinding_factor = hashlib.sha256(
            safe_derive(blinding_xkey, STAGE_BLINDING_ASSET_FACTOR_PATH)
        ).digest()

        if lstage.level_n == 0 and vstage.index_m == 0:
            assert first_stage_input_descriptor is not None
            contract_input_descriptor = first_stage_input_descriptor
            first_stage_input_descriptor = None
        else:
            assert first_stage_input_descriptor is None
            contract_input_descriptor = BlindingInputDescriptor(
                asset=plan.collateral.asset,
                amount=plan.collateral.amount,
                blinding_factor=Uint256(blinding_factor),
                asset_blinding_factor=Uint256(asset_blinding_factor),
            )

        vstage.blinding_data = VerticalProgressionStageBlindingData(
            blinding_xkey, contract_input_descriptor
        )

    collateral_grab_outs_hash = \
        get_hash_of_collateral_forfeiture_checked_outs(
            lstage.vertical_stages[-1],
            creditor_control_asset, debtor_control_asset, bitcoin_asset)

    total_vstages = 0

    # Need to process in reverse, because scripts in earlier stages
    # depend on scripts in later stages
    for vstage in reversed(lstage.vertical_stages):

        total_vstages += 1

        if vstage.next_lateral_stage:
            total_vstages += generate_abl_contract_for_lateral_stage(
                vstage.next_lateral_stage,
                vstage.blinding_data.blinding_xkey,
                start_block_num,
                creditor_control_asset,
                debtor_control_asset,
                bitcoin_asset
            )

        full_repayment_cod = get_full_repayment_checked_outs_data(
            vstage,
            creditor_control_asset,
            debtor_control_asset,
            bitcoin_asset,
        )

        partial_repayment_cod = get_partial_repayment_checked_outs_data(
            vstage,
            creditor_control_asset,
            debtor_control_asset,
            bitcoin_asset,
        )

        revoc_cod = get_revocation_tx_checked_outs_data(
            vstage,
            creditor_control_asset,
            bitcoin_asset
        )

        stage_script, checked_outs_hashes = \
            generate_script_and_checked_outs_hashes(
                vstage,
                creditor_control_asset,
                debtor_control_asset,
                start_block_num,
                full_repayment_checked_outs_data=full_repayment_cod,
                partial_repayment_checked_outs_data=partial_repayment_cod,
                revoc_checked_outs_data=revoc_cod,
                hash_of_collateral_grab_outputs_data=collateral_grab_outs_hash,
            )

        vstage.script_data = VerticalProgressionStageScriptData(
            stage_script, checked_outs_hashes
        )

    return total_vstages
