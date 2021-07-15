# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from typing import Optional

from bitcointx.core import b2x
from bitcointx.core.key import CKey
from bitcointx.core.script import CScript
from bitcointx.wallet import P2WSHCoinAddress
from elementstx.core import CAsset, CAssetIssuance, CElementsTransaction

from .types import (
    RepaymentPlan, LateralProgressionStage, VerticalProgressionStage,
    CheckOutputError
)


def get_vstage_by_script(
    plan: RepaymentPlan, script: CScript
) -> Optional[VerticalProgressionStage]:
    """Return stage that belongs to this script"""

    def find_vstage(
        lstage: LateralProgressionStage
    ) -> Optional[VerticalProgressionStage]:
        for vstage in lstage.vertical_stages:
            current_script = P2WSHCoinAddress.from_redeemScript(
                vstage.script_data.script
            ).to_scriptPubKey()

            if current_script == script:
                return vstage

            if vstage.next_lateral_stage is not None:
                found_stage = find_vstage(vstage.next_lateral_stage)
                if found_stage is not None:
                    return found_stage

        return None

    return find_vstage(plan.first_lateral_stage)


def check_output(
    tx: CElementsTransaction,
    txout_index: int,
    blinding_key: CKey,
    descr: str,
    expected_spk: CScript,
    expected_asset: CAsset,
    expected_amount: int,
) -> None:
    """Check that the output contains expected things
    and return the error string if it contains wrong"""
    txout = tx.vout[txout_index]

    if expected_spk is not None:
        if txout.scriptPubKey != expected_spk:
            raise CheckOutputError(
                f"{descr} output scriptPubKey ({b2x(txout.scriptPubKey)!r}) "
                f"does not match expected scriptPubKey "
                f"({b2x(expected_spk)!r})"
            )

    unblind_result = txout.unblind_confidential_pair(
        blinding_key, tx.wit.vtxoutwit[txout_index].rangeproof
    )

    if unblind_result.error:
        raise CheckOutputError(
            f"cannot unblind {descr} output: {unblind_result.error}"
        )

    if unblind_result.asset != expected_asset:
        raise CheckOutputError(
            f"the unblinded asset ({unblind_result.asset.to_hex()}) "
            f"in {descr} output does not match the expected asset "
            f"({expected_asset.to_hex()})"
        )

    if unblind_result.amount != expected_amount:
        raise CheckOutputError(
            f"the unblinded asset amount ({unblind_result.amount}) "
            f"in {descr} output does not match expected amount "
            f"({expected_amount})"
        )


def check_issuance_amount_1_no_reissuance(
    issuance: CAssetIssuance, asset_name: str
) -> Optional[str]:
    # Make sure that this is unblinded issuance
    if not issuance.assetBlindingNonce.is_null():
        return (
            f"unexpected {asset_name} issuance configuration: "
            f"assetBlindingNonce is not null"
        )
    # Check that the amount of the control_asset issued is 1
    if issuance.nAmount.to_amount() != 1:
        return (
            f"unexpected {asset_name} issuance amount: must be 1, "
            f"but it is {issuance.nAmount.to_amount()}"
        )
    # And that there is no reissuance tokens
    if not issuance.nInflationKeys.is_null():
        return (
            f"unexpected {asset_name} issuance configuration: "
            f"nInflationKeys is not null"
        )
    return None
