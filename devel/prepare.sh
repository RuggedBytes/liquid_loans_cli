#!/bin/bash -ex

# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

shopt -s expand_aliases
alias e1-dae="/root/elements/src/elementsd -datadir=/root/elementsdir1"
alias e1-cli="/root/elements/src/elements-cli -datadir=/root/elementsdir1"
alias e2-dae="/root/elements/src/elementsd -datadir=/root/elementsdir2"
alias e2-cli="/root/elements/src/elements-cli -datadir=/root/elementsdir2"
alias e1-qt="/root/elements/src/qt/elements-qt -datadir=/root/elementsdir1"
alias e2-qt="/root/elements/src/qt/elements-qt -datadir=/root/elementsdir2"
# start the first elemetsd daemon
e1-dae
# start the second elemetsd daemon
e2-dae
# wait for starting
sleep 5
DUMMYADDR="AzpsRJLWcsStb2fg8LFnBSvwsAXo2Mz7Vv1ZymXw4RePmnogcG2dyMvwADqpudSRs2RYHG91hbJAyTnf"
# split all money for two parts
e1-cli sendtoaddress $(e1-cli getnewaddress) 21000000 "" "" true
e1-cli generatetoaddress 101 $DUMMYADDR
e1-cli sendtoaddress $(e2-cli getnewaddress) 10500000 "" "" false
e1-cli generatetoaddress 101 $DUMMYADDR

e1-cli getwalletinfo
e2-cli getwalletinfo

exec /root/split.py

