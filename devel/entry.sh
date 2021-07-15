# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#!/usr/bin/env bash
set -e

/root/elements/src/elementsd -datadir=/root/elementsdir1 -reindex
/root/elements/src/elementsd -datadir=/root/elementsdir2 -reindex
# wait for starting demons
sleep 6
export LD_LIBRARY_PATH=/usr/local/lib
export LC_ALL=C.UTF-8
export LANG=C.UTF-8
exec "$@"
