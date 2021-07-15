#!/usr/bin/env python3

# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import logging
import os
from random import randint

from bitcointx import ChainParams
from bitcointx.core import str_money_value
from bitcointx.core.key import CKey
from bitcointx.rpc import RPCCaller
from bitcointx.wallet import P2WPKHCoinAddress
from elementstx.wallet import CCoinConfidentialAddress

logging.basicConfig(filename="debug.log", level=logging.DEBUG)

elements_chain_name = "elements"

SERVICE_URL1 = "http://user1:password1@localhost:18884"
SERVICE_URL2 = "http://user2:password2@localhost:18885"

print("Split one big utxo to some small pieces")

num_txo_in_tx = 50
num_tx_in_block = 50

num_big_utxo = 50
initial_balance = 10_000_000
num_needed_utxo = 1_000_000


def get_random_amnt() -> str:
    return str_money_value(randint(700, 100000))


def get_random_addr() -> CCoinConfidentialAddress:
    blinding_key = CKey.from_secret_bytes(os.urandom(32))
    key = CKey.from_secret_bytes(os.urandom(32))
    addr = CCoinConfidentialAddress.from_unconfidential(
        P2WPKHCoinAddress.from_pubkey(key.pub), blinding_key.pub
    )
    return addr


with ChainParams(elements_chain_name):
    elt_rpc1 = RPCCaller(service_url=SERVICE_URL1)
    elt_rpc2 = RPCCaller(service_url=SERVICE_URL2)

with ChainParams(elements_chain_name):
    # split one big utxo
    # first daemon
    addrs = {elt_rpc2.getnewaddress(): 100 + w * 2 for w in range(20)}
    elt_rpc2.sendmany("", addrs)
    elt_rpc2.generatetoaddress(1, str(get_random_addr()))
    # second daemon
    addrs = {elt_rpc1.getnewaddress(): 100 + w * 2 for w in range(20)}
    elt_rpc1.sendmany("", addrs)
    elt_rpc1.generatetoaddress(1, str(get_random_addr()))
