# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import time
from decimal import Decimal
from typing import List, Dict, Iterator, Optional, Tuple, Union, Any

from bitcointx.core import (
    COutPoint,
    b2lx,
    b2x,
    lx,
    satoshi_to_coins,
    x,
    Uint256,
)
from bitcointx.core.key import CKey
from bitcointx.core.script import CScript
from bitcointx.rpc import JSONRPCError
from bitcointx.wallet import P2WSHCoinAddress
from elementstx.core import (
    BlindingInputDescriptor,
    CAsset,
    CElementsTransaction,
    CElementsOutPoint,
)

from .constants import (
    DEFAULT_TX_SIZE, CONTRACT_COLLATERAL_OUT_INDEX
)
from .scripts import get_control_script
from .types import (
    Amount,
    BlindedInputInfo,
    ContractTransaction,
    ContractMutableTransaction,
    RepaymentPlan,
    VerticalProgressionStage,
    LateralProgressionStage,
    CreditorAsset,
    BitcoinAsset,
    ElementsRPCCaller
)
from .types import DataLookupError


def get_utxo_by_outpoint(
    rpc: ElementsRPCCaller, outpoint: COutPoint
) -> Optional[Dict[str, Any]]:
    """Search the utxo dict in rpc wallet by index and txid"""

    txid = b2lx(outpoint.hash)

    def filter_func(utxo: Optional[Dict[str, Any]]
                    ) -> bool:
        if utxo is None:
            return False
        assert isinstance(utxo["txid"], str)
        assert isinstance(utxo["vout"], int)
        return utxo["txid"] == txid and utxo["vout"] == outpoint.n

    return next(filter(filter_func, rpc.listunspent(0, 9999999)), None)


def find_asset_utxo_by_min_amount(
    rpc: ElementsRPCCaller, asset: CAsset, amount: int
) -> Optional[Dict[str, Any]]:
    """Search the first utxo dict in rpc wallet that has enough amount"""
    assert amount >= 0
    asset_utxos = rpc.listunspent(
        0, 9999999, [], False, {"asset": asset.to_hex()}
    )

    def filter_func(utxo: Optional[Dict[str, Any]]
                    ) -> bool:
        if utxo is None:
            return False
        return Amount(utxo["amount"]) >= amount

    return next(filter(filter_func, asset_utxos), None)


def find_blinded_asset_utxo_by_min_amount(
    rpc: ElementsRPCCaller, asset: CAsset, amount: int
) -> Optional[Dict[str, Any]]:
    """Search the first utxo dict in rpc wallet that has enough amount"""
    assert amount >= 0
    asset_utxos = rpc.listunspent(
        0, 9999999, [], False, {"asset": asset.to_hex()}
    )

    def filter_func(utxo: Optional[Dict[str, Any]]
                    ) -> bool:
        if utxo is None:
            return False
        return Amount(utxo["amount"]) >= amount and "amountcommitment" in utxo

    return next(filter(filter_func, asset_utxos), None)


def find_asset_utxo_by_amount(
    rpc: ElementsRPCCaller, asset: CAsset, amount: int
) -> Optional[Dict[str, Any]]:
    """Search the first utxo dict in rpc wallet that has a certainly amount"""
    assert amount >= 0
    asset_utxos = rpc.listunspent(
        0, 9999999, [], False, {"asset": asset.to_hex()}
    )

    def filter_func(utxo: Optional[Dict[str, Any]]) -> bool:
        if utxo is None:
            return False
        return Amount(utxo["amount"]) == amount

    return next(filter(filter_func, asset_utxos), None)


def make_utxo(
    rpc: ElementsRPCCaller, amount: int, asset: CAsset
) -> BlindedInputInfo:
    """Create utxo with needed amount and type"""
    addr = rpc.getnewaddress()
    rpc.sendtoaddress(
        addr,
        satoshi_to_coins(amount),
        "",
        "",
        False,
        False,
        1,
        "CONSERVATIVE",
        asset.to_hex(),
        False,
    )
    (utxo,) = rpc.listunspent(0, 3, [addr], False, {"asset": asset.to_hex()})
    return parse_utxo_dict(utxo)


def parse_utxo_dict(utxo: Dict[str, Any]
                    ) -> BlindedInputInfo:
    assert isinstance(utxo['txid'], str)
    assert isinstance(utxo['asset'], str)
    assert isinstance(utxo['amountblinder'], str)
    assert isinstance(utxo['assetblinder'], str)
    assert isinstance(utxo['vout'], int)
    assert isinstance(utxo['amount'], Decimal)
    return BlindedInputInfo(
        CElementsOutPoint(lx(utxo["txid"]), utxo["vout"]),
        BlindingInputDescriptor(
            asset=CAsset(lx(utxo["asset"])),
            amount=Amount(utxo["amount"]),
            blinding_factor=Uint256(lx(utxo["amountblinder"])),
            asset_blinding_factor=Uint256(lx(utxo["assetblinder"])),
        ),
    )


def sign_tx_with_wallet(
    rpc: ElementsRPCCaller, tx: CElementsTransaction
) -> ContractMutableTransaction:
    """Sign transaction with wallet"""
    backup = {
        idx: wit
        for idx, wit in enumerate(tx.wit.vtxinwit)
        if not wit.is_null()
    }
    signedtx = rpc.signrawtransactionwithwallet(b2x(tx.serialize()), [], "ALL")
    tx = ContractMutableTransaction.deserialize(x(signedtx["hex"]))
    for idx, wit in backup.items():
        tx.wit.vtxinwit[idx] = wit.to_mutable()
    return tx


def chain_txs(
    rpc: ElementsRPCCaller, from_block: int, to_block: int
) -> Iterator[Tuple[Dict[str, Any], int]]:
    """Return iterator on transactions in the blockchain"""
    assert from_block <= to_block, \
        f"from_block ({from_block}) must be <= to_block ({to_block})"
    for block_num in range(to_block, from_block - 1, -1):
        block = rpc.getblock(rpc.getblockhash(block_num), 2)
        for tx_dict in block["tx"]:
            yield tx_dict, block_num


def track_tx_by_prevouts(
    prev_txid_str: str,
    rpc: ElementsRPCCaller,
    *,
    prev_txout_index: int,
    from_block: int,
    to_block: int,
) -> Optional[ContractTransaction]:
    for tx_dict, block_num in chain_txs(rpc, from_block, to_block):
        if len(tx_dict["vin"]) < 2:
            continue
        for vin in tx_dict["vin"][:2]:
            if (
                vin.get("txid") == prev_txid_str
                and vin["vout"] == prev_txout_index
            ):
                tx = ContractTransaction.deserialize(x(tx_dict["hex"]))
                tx.block_num = block_num
                return tx

    return None


def track_contract_txs(
    prev_txid_str: str,
    rpc: ElementsRPCCaller,
    *,
    prev_txout_index: int,
    from_block: int,
    to_block: int,
    plan: Optional[RepaymentPlan] = None
) -> Tuple[List[ContractTransaction], List[VerticalProgressionStage]]:
    """Return the transaction that spends collateral or principal"""
    # search in blockchain
    assert to_block >= 1
    assert from_block >= 1

    from_block_orig = from_block

    if plan:
        script_map = {}

        def make_map_from_plan(lstage: LateralProgressionStage) -> None:
            for vstage in lstage.vertical_stages:
                current_spk = P2WSHCoinAddress.from_redeemScript(
                    vstage.script_data.script
                ).to_scriptPubKey()
                script_map[current_spk] = vstage
                if vstage.next_lateral_stage is not None:
                    make_map_from_plan(vstage.next_lateral_stage)

        make_map_from_plan(plan.first_lateral_stage)
        script_set = set(script_map.keys())

    contract_tx_list = []
    vstage_list = []
    while True:
        tx = track_tx_by_prevouts(
            prev_txid_str, rpc, prev_txout_index=prev_txout_index,
            from_block=from_block, to_block=to_block)

        if tx is None:
            break

        contract_tx_list.append(tx)

        if plan:
            spk = tx.vout[0].scriptPubKey
            if spk in script_set:
                vstage_list.append(script_map[spk])
            else:
                # we are not in the contract-defined stages anymore
                break

        prev_txid_str = b2lx(tx.GetTxid())
        prev_txout_index = CONTRACT_COLLATERAL_OUT_INDEX

        from_block = tx.block_num

    if not contract_tx_list:
        raise DataLookupError(
            f"Could not find contract tx from {from_block_orig} to {to_block}"
        )

    if len(contract_tx_list) > len(vstage_list):
        assert len(contract_tx_list) == len(vstage_list)+1, \
            "only one tx must be collected beyond contract stages"

    return contract_tx_list, vstage_list


def find_all_payments(
    contract_tx_list: List[ContractTransaction],
    creditor_control_asset: CreditorAsset,
    rpc: ElementsRPCCaller,
) -> List[Tuple[str, int, int]]:
    """Return all payments that are not spent for this plan"""
    creditor_control_scriptpubkey = P2WSHCoinAddress.from_redeemScript(
        get_control_script(creditor_control_asset)
    ).to_scriptPubKey()

    all_payments: List[Tuple[str, int, int]] = []

    for tx_idx, tx in enumerate(contract_tx_list):
        # the payment must be in the first two outputs
        for n, outp in enumerate(tx.vout[:2]):
            if outp.scriptPubKey == creditor_control_scriptpubkey:
                txid = b2lx(tx.GetTxid())
                if rpc.gettxout(txid, n) is not None:
                    all_payments.append((txid, n, tx_idx))

    return all_payments


def get_blinding_key_for_script(rpc: ElementsRPCCaller, spk: CScript) -> CKey:
    """Return the blinding_key for this pubkey script"""
    decoded = rpc.decodescript(b2x(spk))
    address_info = rpc.getaddressinfo(decoded["addresses"][0])
    blinding_key = rpc.dumpblindingkey(address_info["confidential"])
    return CKey(x(blinding_key))


def is_scriptpubkey_mine(rpc: ElementsRPCCaller, spk: CScript) -> bool:
    """Check that this script belongs this rpc wallet"""
    decoded = rpc.decodescript(b2x(spk))
    if "addresses" not in decoded:
        return False
    address_info = rpc.getaddressinfo(decoded["addresses"][0])
    assert isinstance(address_info["ismine"], bool)
    return address_info["ismine"]


def calculate_fee(
    rpc: ElementsRPCCaller,
    size: int = DEFAULT_TX_SIZE,
    depth: int = 6,
    default_fee: Decimal = Decimal("0.0001"),
) -> int:
    assert depth > 0
    assert size > 0
    size_kb = Decimal(size) / Decimal(1000)
    try:
        smart_fee_result = rpc.estimatesmartfee(depth)
    except JSONRPCError:
        fee_per_kb = Amount(default_fee)
    else:
        fee_per_kb_value = smart_fee_result.get("feerate", default_fee)
        if fee_per_kb_value < 0:
            raise RuntimeError(
                f"the estimatesmartfee returns wrong value {fee_per_kb_value}"
            )
        fee_per_kb = Amount(fee_per_kb_value)

    return int(fee_per_kb * size_kb)


def wait_confirm(
    txid: Union[str, bytes],
    rpc: ElementsRPCCaller,
    num_confirms: int = 2,
    until_block: Optional[int] = None,
) -> bool:
    """Wait for particular transaction to be confirmed.
    generate test blocks if it is in mempool, but not confirmed.
    raise Exception if not confirmed in 60 seconds"""
    assert num_confirms >= 0

    if isinstance(txid, bytes):
        assert len(txid) == 32
        txid = b2lx(txid)

    num_seconds = 0
    for _ in range(num_confirms * 2 + 60):
        for _ in range(30):
            try:
                tx_dict = rpc.getrawtransaction(txid, 1)
                confirms = tx_dict.get("confirmations", 0)

                if until_block is not None and confirms > 0:
                    height = rpc.getblock(tx_dict["blockhash"])["height"]
                    num_confirms = until_block - height

                if confirms >= num_confirms:
                    height = rpc.getblockchaininfo()["blocks"]
                    return True

                time.sleep(1)
                num_seconds += 1
                break
            except JSONRPCError as e:
                if e.error["code"] == -5:
                    pass
                num_seconds += 1
                time.sleep(1)
                # no break, continue inner cycle
        else:
            # all tries ended in error, break from outer cycle
            break

    raise TimeoutError("timed out waiting for confirmation")


def get_fee_utxo(
    rpc: ElementsRPCCaller, amount: int, bitcoin_asset: BitcoinAsset
) -> BlindedInputInfo:
    """Return utxo to pay fee"""
    # Search appropriate utxo
    assert amount > 0
    bitcoin_utxos = rpc.listunspent(
        1, 9999999, [], False, {"asset": bitcoin_asset.to_hex()}
    )
    if not bitcoin_utxos:
        raise DataLookupError("There is no utxo to pay fee")

    filtered_bitcoin_utxos = (
        utxo
        for utxo in bitcoin_utxos
        if Amount(utxo["amount"]) >= amount and "amountcommitment" in utxo
    )
    fee_utxo = next(filtered_bitcoin_utxos, None)
    if fee_utxo is None:
        raise DataLookupError(
            "There is no single utxo that has an amount enough to pay the fee")

    return parse_utxo_dict(fee_utxo)


def issue_asset(
    rpc: ElementsRPCCaller, asset_amount: int, blind: bool = True
) -> Tuple[str, str, int]:
    """Issue asset and return CAsset instance and utxo to spend"""

    # No reissuance, so we specify tokenamount as 0
    issue = rpc.issueasset(satoshi_to_coins(asset_amount), 0, blind)
    return issue["asset"], issue["txid"], issue["vin"]


def get_bitcoin_asset(rpc: ElementsRPCCaller) -> BitcoinAsset:
    return BitcoinAsset(lx(rpc.dumpassetlabels()['bitcoin']))
