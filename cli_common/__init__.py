# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import copyreg
import hashlib
import json
import pickle
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Dict, Any, Tuple, Type, cast

import click
from bitcointx.core import CTransaction, b2x, coins_to_satoshi, Uint256
from bitcointx.rpc import JSONRPCError
from bitcointx.wallet import CCoinExtKey
from elementstx.core import CAsset
from elementstx.wallet import CElementsExtKey

from lib.rpc_utils import wait_confirm
from lib.types import (
    Amount, PlanData, RepaymentPlan,
    Rates, RPCPathParamType, BlockchainNetworkType, ElementsRPCCaller
)
from io import BytesIO


data_option = click.option(
    "-d",
    "--data",
    type=click.Path(
        exists=True,
        dir_okay=False,
        resolve_path=True,
    ),
    help="path to the file that contains debtor/creditor data",
    required=True,
)


rpc_option = click.option(
    "-r",
    "--rpc",
    type=RPCPathParamType(),
    help="path to elements.conf or liquid.conf, or url for rpc service",  # noqa
    required=True,
)


plan_option = click.option(
    "-p",
    "--plan",
    type=click.Path(
        exists=True,
        dir_okay=False,
        resolve_path=True,
    ),
    help="path to the file that contains repayment plan",
    required=True,
)


force_option = click.option(
    "-f",
    "--force",
    "force",
    is_flag=True,
    help="Do not ask for user's confirmation when creating new UTXO"
    " (and paying the fee for that)",
)


min_output_option = click.option(
    "--min-output",
    "min_output",
    type=int,
    default=1,
    help="minimum value for transaction outputs",
)

network_option = click.option(
    "--network",
    "network",
    type=BlockchainNetworkType(),
    default="elements",
    help="blockchain network name [\"elements\" | \"liquidv1\"]",
)


def read_plandata(filename: str) -> PlanData:
    with click.open_file(filename) as f:
        try:

            v = json.load(f)
            rv = v['rates']
            rates = Rates(
                rate_due=rv['rate_due'],
                rate_early=rv['rate_early'],
                rate_collateral_penalty=rv['rate_collateral_penalty'],
                rates_late=rv['rates_late'])

            return PlanData(
                    principal_asset=v['principal_asset'],
                    principal_amount=v['principal_amount'],
                    collateral_asset=v['collateral_asset'],
                    collateral_amount=v['collateral_amount'],
                    N=v['N'], S=v['S'],
                    rates=rates,
                    num_blocks_in_period=v['num_blocks_in_period'],
                    amount_C_uncond=v['amount_C_uncond']
            )

        except json.JSONDecodeError as e:
            raise click.ClickException(
                f"Error reading the file: {filename}: {e}"
            )


def hash_str(data_str: str) -> str:
    """Return hex hash data_string
    """
    return hashlib.sha256(bytes(data_str, "utf-8")).hexdigest()


def load_data_with_checking_hash(file: str) -> Dict[str, Any]:
    """Load hashed json data from file and check it
    """
    with click.open_file(file) as f:
        check_hash = f.read(64)
        expected_newline = f.read(1)
        if expected_newline != "\n":
            raise click.ClickException(
                "Newline not found on position 64 in the file")
        str_data = f.read()
        hash_data = hash_str(str_data)
        if check_hash != hash_data:
            raise click.ClickException("File was changed. Hash is not correct")
        try:
            data = json.loads(str_data)
            assert all(isinstance(k, str) for k in data.keys())
            return cast(Dict[str, Any], data)
        except json.JSONDecodeError as e:
            raise click.ClickException(f"Error reading the file: {file}: {e}")


def read_aux_data(filename: str) -> Dict[str, Any]:
    return load_data_with_checking_hash(filename)


def save_to_json_with_hash(filename: str, data: Dict[str, Any]) -> None:
    json_data = json.dumps(data, indent=4)
    hash_data = hash_str(json_data) + "\n"
    with click.open_file(filename, mode="w") as f:
        f.write(hash_data)
        f.write(json_data)


def get_cache_file_name(contract_hash: Uint256) -> str:
    return f".{b2x(contract_hash.data)}.cache"


def reduce_CAsset(c: CAsset) -> Tuple[Type[CAsset], Tuple[bytes]]:
    return CAsset, (c.data,)


def reduce_CCoinExtKey(c: CCoinExtKey) -> Tuple[Type[CCoinExtKey], Tuple[str]]:
    return CCoinExtKey, (str(c),)


def get_digest(file_path: str) -> str:
    h = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(h.block_size)
            if not chunk:
                break
            h.update(chunk)

    return h.hexdigest()


def dump_repayment_plan(plan: RepaymentPlan, file: Path) -> None:
    dump_file = BytesIO()
    p = pickle.Pickler(dump_file)
    p.dispatch_table = copyreg.dispatch_table.copy()  # type: ignore
    p.dispatch_table[CAsset] = reduce_CAsset  # type: ignore
    p.dispatch_table[CCoinExtKey] = reduce_CCoinExtKey  # type: ignore
    p.dispatch_table[CElementsExtKey] = reduce_CCoinExtKey  # type: ignore
    p.dump(plan)

    hash_data = hashlib.sha256(dump_file.getbuffer()).digest()
    assert len(hash_data) == 32

    with file.open(mode="wb") as f:
        f.write(hash_data)
        f.write(dump_file.getbuffer())


def load_repayment_plan(file: Path) -> RepaymentPlan:
    with file.open(mode="rb") as f:
        hash_data = f.read(32)
        data = BytesIO(f.read())

    file_hash = hashlib.sha256(data.getbuffer()).digest()

    if file_hash != hash_data:
        raise click.ClickException("The plan cache file was corrupted")

    plan = pickle.load(data)
    assert isinstance(plan, RepaymentPlan)
    return plan


def asset_amount_is_enough(
    rpc: ElementsRPCCaller,
    amount: int,
    asset: CAsset,
    minconf: int = 0,
    include_watchonly: bool = False,
) -> bool:
    """Check that the amount is enough"""
    try:
        balance = rpc.getbalance(
            "*", minconf, include_watchonly, asset.to_hex()
        )
    except JSONRPCError as e:
        raise click.ClickException(
            f"Can't get balance for asset {asset.to_hex()}: {e}"
        )

    try:
        balance = coins_to_satoshi(Decimal(balance))
    except (ValueError, InvalidOperation):
        raise click.ClickException(
            f"Can't parse balance from rpc daemon {balance}"
        )

    return True if Amount(balance) >= amount else False


def print_psbt(rpc: ElementsRPCCaller, tx: CTransaction) -> None:
    """Print the psbt to the console"""
    psbt_str = rpc.converttopsbt(b2x(tx.serialize()), True, True)
    click.echo(f"psbt: {psbt_str}")


def send_tx_with_confirm(rpc: ElementsRPCCaller, tx: CTransaction) -> str:
    """Send the transaction and wait for 1 confirmation"""
    txid = rpc.sendrawtransaction(b2x(tx.serialize()))
    assert isinstance(txid, str)
    wait_confirm(txid, rpc, num_confirms=1)
    return txid
