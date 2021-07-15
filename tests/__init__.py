# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import time
from typing import Optional, Union, Iterator

import elementstx  # noqa: F401
from bitcointx.core import b2lx
from bitcointx.rpc import JSONRPCError, RPCCaller

WAIT_TIME = 30


def timer(timeout: int) -> Iterator[None]:
    """One second generator"""
    # TODO: Add return type
    for _ in range(timeout):
        yield
        time.sleep(1)


def sync_rpc(rpc1: RPCCaller, rpc2: RPCCaller) -> None:
    """Wait for syncing blockchain len between daemons"""
    for _ in timer(WAIT_TIME):
        if rpc1.getbestblockhash() == rpc2.getbestblockhash():
            break
    else:
        raise TimeoutError(
            f"best blockhash rpc1 is not equal best blockhash rpc1"
            f"for {WAIT_TIME} seconds"
        )


def wait_confirm(
    txid: Union[str, bytes],
    rpc: RPCCaller,
    num_confirms: int = 2,
    until_block: Optional[int] = None,
) -> bool:
    """Wait for particular transaction to be confirmed.
    generate test blocks if it is in mempool, but not confirmed.
    raise Exception if not confirmed in 60 seconds"""

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

                num_confirms_left = num_confirms - confirms
                if num_confirms_left > 0:
                    time.sleep(1)
                    num_seconds += 1
                break
            except JSONRPCError as e:
                if e.error["code"] == -5:
                    pass
            num_seconds += 1
            time.sleep(1)
        else:
            break
        rpc.generatetoaddress(
            1,
            "AzpvSxwnsiFszRZfmTRGcwgEqgcsbyF4m8AJ"
            "vir68HHxo4KqSyABCnrY46GebX45yxAJnWmbFarLwYQq",
        )

    raise TimeoutError("timed out waiting for confirmation")
