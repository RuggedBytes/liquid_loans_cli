# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# sizes for all types of loan transactions
DEFAULT_TX_SIZE = 6580
DEBT_RETURN_TX_APPROX_SIZE = 4276
COMMON_TX_APPROX_SIZE = 2962

BLINDING_DERIVATION_PREFIX = "m/0h/2h/"

LOCKED_COLLATERAL_PATH = BLINDING_DERIVATION_PREFIX + "1h/0h"
SEED_CONTRACT_TX_PATH = BLINDING_DERIVATION_PREFIX + "2h/2h"
STAGE_BLINDING_FACTOR_PATH = "4h/0h"
STAGE_BLINDING_ASSET_FACTOR_PATH = "4h/1h"
STAGE_NEXT_LEVEL_PATH = "1000000000h"
BLIND_PUB_COLLATERAL_RETURN_TX_PATH = "1h/0h/0h"
BLIND_PUB_COLLATERAL_RETURN_DEBT_TX_PATH = "1h/1h/0h"
BLIND_PUB_PAYMENT_RETURN_DEBT_TX_PATH = "1h/1h/1h"
BLIND_PUB_COLLATERAL_REVOKE_TX_PATH = "1h/2h/0h"
BLIND_PUB_COLLATERAL_GRAB_TX_PATH = "5h/1h"
SEED_RETURN_DEBT_TX_PATH = "2h/1h"
SEED_RETURN_TX_PATH = "2h/0h"
SEED_REVOKE_TX_PATH = "2h/2h"
SEED_GRAB_TX_PATH = "6h/0h"


# bitcoin specific constants
MIN_GUARANTEED_CHANGE = 546


# XXX We have a poor way to measure the custom-random data consumption
# by the blinding function, based on that there should be 4 calls
# to random func with len=32 for each blinding (both output and issuance)
# This is is not based on thorough analysis of the blinding algorithm,
# but rather on just an observation.
# The correct way to hande it is to pass parameters to _rand_func of
# blind() method, where these parameters would give the info on what the
# requested random data will be used for (which output, what blinding
# sub-function, etc)
RANDOM_BYTES_PER_BLINDING_FACTORS = 32 * 2
RANDOM_BYTES_PER_BLINDING_PROOFS = 32 * 2
RANDOM_BYTES_PER_UNIT_BLINDING = (
    RANDOM_BYTES_PER_BLINDING_FACTORS + RANDOM_BYTES_PER_BLINDING_PROOFS
)

CONTRACT_COLLATERAL_INP_INDEX = 0
CONTRACT_COLLATERAL_OUT_INDEX = 0

CONTRACT_PRINCIPAL_INP_INDEX = 1
CONTRACT_PRINCIPAL_OUT_INDEX = 1

CONTRACT_CREDITOR_CONTROL_OUT_INDEX = 2
CONTRACT_DEBTOR_CONTROL_OUT_INDEX = 3

MUTUAL_DEBTOR_OUT_INDEX = 2

MIN_NUM_CONTRACT_OUTPUT = 5
MIN_NUM_CONTRACT_INPUT = 3
