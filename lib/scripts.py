# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# pylama:ignore=E501

from io import BytesIO
from typing import Tuple, List

import ecdsa
from bitcointx.core import x
from bitcointx.core.script import (
    ScriptElement_Type,
    OP_1,
    OP_CAT,
    OP_CHECKSIG,
    OP_CODESEPARATOR,
    OP_DUP,
    OP_EQUALVERIFY,
    OP_FROMALTSTACK,
    OP_HASH256,
    OP_LEFT,
    OP_LSHIFT,
    OP_OVER,
    OP_ROT,
    OP_SHA256,
    OP_SIZE,
    OP_SUBSTR,
    OP_SWAP,
    OP_TOALTSTACK,
    CScript,
)
from elementstx.core import (
    CAsset, CConfidentialAsset, CConfidentialValue, CElementsTxOut
)
from elementstx.core.script import OP_CHECKSIGFROMSTACKVERIFY


def get_known_k_r() -> Tuple[bytes, bytes]:
    # Known k value that would give smallest
    # x coordinate for R (21 byte length). See:
    # https://crypto.stackexchange.com/questions/60420/what-does-the-special-form-of-the-base-point-of-secp256k1-allow
    # https://bitcointalk.org/index.php?topic=289795.msg3183975#msg3183975
    k = (ecdsa.SECP256k1.order + 1) // 2
    r = ecdsa.SECP256k1.generator * k

    return k, r.x()


def get_known_r_data() -> bytes:
    _, r = get_known_k_r()
    return bytes(ecdsa.util.number_to_string(r, ecdsa.SECP256k1.order).lstrip(
        b"\x00"
    ))


# ============================ #
# Prepare various script parts #
# ============================ #
# fmt: off
covenant_post_codesep_ops: List[ScriptElement_Type] = [
    # check the constructed transaction data
    # stack:                     # pub sighash_preimage sig pub sig+SIGHASH_ALL
    OP_CHECKSIGFROMSTACKVERIFY,  # pub sig+SIGHASH_ALL
    # check that the transaction
    # matches the sighash checked by CHECKSIGFROMSTACKVERIFY
    OP_CHECKSIG,
]

covenant_outputs_check_ops: List[ScriptElement_Type] = [
    # stack:        # outs_data lcktime sighash_data_pfx sig_pfx sig_sfx
    OP_HASH256,     # hashOuts lcktime sighash_data_pfx sig_pfx sig_sfx
    OP_SWAP,        # lcktime hashOuts sighash_data_pfx sig_pfx sig_sfx
    OP_SIZE,        # lcktime_size lcktime hashOuts sighash_data_pfx sig_pfx sig_sfx
    4,              # 4 lcktime_size lcktime hashOuts sighash_data_pfx sig_pfx sig_sfx
    OP_EQUALVERIFY,  # lcktime hashOuts sighash_data_pfx sig_pfx sig_sfx
    OP_CAT,         # hashOuts+lcktime sighash_data_pfx sig_pfx sig_sfx
    # NOTE: this is SIGHASH_ALL as it appears in sighash data, thus 4 bytes
    x(
        "01000000"
    ),              # SIGHASH_ALL hashOuts+lcktime sighash_data_pfx sig_pfx sig_sfx
    OP_CAT,         # sighash_data_sfx sighash_data_pfx sig_pfx sig_sfx
    OP_CAT,         # sighash_data sig_pfx sig_sfx
    # SHA256 and not HASH256 because
    # CHECKSIGFROMSTACKVERIFY does another SHA256
    OP_SHA256,      # sighash_preimage sig_pfx sig_sfx
    OP_TOALTSTACK,  # sig_pfx sig_sfx                       | sighash_preimage
    get_known_r_data(),
    #               # r_data sig_pfx sig_sfx                | sighash_preimage
    # construct known-small pub prefix: 020000000000000000000000
    # it is 12 bytes (+1 byte PUSHDATA), but with this code we use only 8.
    # It takes 01, shits it, to get data string with 11 zero bytes
    # ending with 01, strips that 01 with LEFT, and then CATs with 02
    2,
    1,
    11 * 8,
    OP_LSHIFT,
    11,
    OP_LEFT,
    OP_CAT,
    #               # pub_pfx r_data sig_pfx sig_sfx        | sighash_preimage
    OP_OVER,        # r_data pub_pfx r_data sig_pfx sig_sfx | sighash_preimage
    OP_CAT,         # pub r_data sig_pfx sig_sfx            | sighash_preimage
    OP_TOALTSTACK,  # r_data sig_pfx sig_sfx         | pub sighash_preimage
    OP_CAT,         # sig_pfx+r_data sig_sfx                | pub sighash_preimage
    OP_SWAP,        # sig_sfx sig_pfx+r_data                | pub sighash_preimage
    OP_CAT,         # sig                                   | pub sighash_preimage
    OP_DUP,         # sig sig                               | pub sighash_preimage
    # NOTE: this is SIGHASH_ALL as it appears
    # in the signature, just one byte.
    OP_1,           # SIGHASH_ALL sig sig                   | pub sighash_preimage
    OP_CAT,         # sig+SIGHASH_ALL sig                   | pub sighash_preimage
    OP_FROMALTSTACK,
    #               # pub sig+SIGHASH_ALL sig               | sighash_preimage
    OP_ROT,         # sig pub sig+SIGHASH_ALL               | sighash_preimage
    OP_OVER,        # pub sig pub sig+SIGHASH_ALL           | sighash_preimage
    OP_FROMALTSTACK,
    #               # sighash_preimage pub sig pub sig+SIGHASH_ALL
    OP_SWAP,        # pub sighash_preimage sig pub sig+SIGHASH_ALL
    OP_CODESEPARATOR,
]
covenant_outputs_check_ops += covenant_post_codesep_ops

covenant_outputs_hash_lookup_ops: List[ScriptElement_Type] = [
    # stack:        # hashes_array offset checked_outs_data other_outs_data ...
    #               # ... lcktime other_sighash_data sig_pfx sig_sfx
    OP_SWAP,        # offset hashes_array checked_outs_data other_outs_data ...
    5,
    OP_LSHIFT,      # offset hashes_array checked_outs_data other_outs_data ...
    32,             # 32 offset hashes_array checked_outs_data other_outs_data ...
    OP_SUBSTR,      # chosen_hash checked_outs_data other_outs_data ...
]

covenant_outputs_hash_check_ops: List[ScriptElement_Type] = [
    # stack:        # chosen_hash checked_outs_data other_outs_data ...
    OP_OVER,        # checked_outs_data chosen_hash checked_outs_data other_outs_data ...
    OP_SHA256,      # sha2(checked_outs_data) chosen_hash checked_outs_data other_outs_data ...
    OP_EQUALVERIFY,
    #               # checked_outs_data other_outs_data lcktime other_sighash_data sig_pfx sig_sfx
    # We like to have checked outputs first in tx.vout, so need this SWAP
    OP_SWAP,        # other_outs_data checked_outs_data lcktime other_sighash_data sig_pfx sig_sfx
    OP_CAT,         # outs_data lcktime other_sighash_data sig_pfx sig_sfx
]
# fmt: on


def get_control_asset_out_data_sans_scriptpubkey(
    control_asset: CAsset,
) -> bytes:

    creditor_control_output_template = CElementsTxOut(
        nValue=CConfidentialValue(1), nAsset=CConfidentialAsset(control_asset)
    )
    b_io = BytesIO()
    creditor_control_output_template.nAsset.stream_serialize(b_io)
    creditor_control_output_template.nValue.stream_serialize(b_io)
    creditor_control_output_template.nNonce.stream_serialize(b_io)

    return bytes(b_io.getbuffer())


def get_control_script(control_asset: CAsset) -> CScript:
    control_script_ops: List[ScriptElement_Type] = [
        # stack:
        # outs_data_sfx lcktime other_sighash_data sig_pfx sig_sfx
        get_control_asset_out_data_sans_scriptpubkey(control_asset),
        # stack:
        # cdata outs_data_sfx lcktime other_sighash_data sig_pfx sig_sfx
        OP_SWAP,
        # stack:
        # partial_outs_data cdata lcktime other_sighash_data sig_pfx sig_sfx
        OP_CAT,
        # stack:
        # outs_data lcktime other_sighash_data sig_pfx sig_sfx
    ]
    control_script_ops += covenant_outputs_check_ops
    return CScript(control_script_ops)
