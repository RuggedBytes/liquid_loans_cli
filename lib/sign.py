# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import struct
from io import BytesIO
from typing import List, Optional

import ecdsa
from bitcointx.core import Hash
from bitcointx.core.script import (
    SIGHASH_ALL,
    SIGVERSION_WITNESS_V0,
    CScript,
    CScriptWitness,
    ScriptElement_Type,
)
from bitcointx.core.serialize import BytesSerializer
from elementstx.core import (
    CConfidentialValue, CElementsMutableTransaction,
    CElementsMutableTxInWitness
)
from elementstx.core.script import CElementsScript

from .scripts import covenant_post_codesep_ops, get_known_k_r


def sign_for_covenant(
    tx: CElementsMutableTransaction,
    input_index: int,
    witness_extra: List[ScriptElement_Type],
    checked_outs_data: Optional[bytes],
    other_outs_data: bytes,
    prev_amount: CConfidentialValue,
    control_script: CScript,
) -> None:
    """Sign the transaction input that is protected by covenant"""
    covenant_post_codesep_script = CElementsScript(covenant_post_codesep_ops)
    serialize_sequence = b"".join(
        struct.pack("<I", inp.nSequence) for inp in tx.vin
    )
    hashSequence = Hash(serialize_sequence)

    serialize_prevouts = b"".join(vin.prevout.serialize() for vin in tx.vin)
    hashPrevouts = Hash(serialize_prevouts)

    assert all(inp.assetIssuance.is_null() for inp in tx.vin)
    hashIssuance = Hash(b"\x00" * len(tx.vin))
    f = BytesIO()

    BytesSerializer.stream_serialize(covenant_post_codesep_script, f)
    convenant_check_scipt_data = bytes(f.getbuffer())

    sighash_preimage_data_pfx = (
        struct.pack("<i", tx.nVersion)
        + hashPrevouts
        + hashSequence
        + hashIssuance
        + tx.vin[input_index].prevout.serialize()
        + convenant_check_scipt_data
        + prev_amount.commitment
        + struct.pack("<I", tx.vin[input_index].nSequence)
        # assetIssuance is null - not including it
    )

    k, r = get_known_k_r()
    key_bytes = ecdsa.util.number_to_string(k, ecdsa.SECP256k1.order)

    rkey = ecdsa.keys.SigningKey.from_string(key_bytes, curve=ecdsa.SECP256k1)

    r = ecdsa.util.number_to_string(r, ecdsa.SECP256k1.order).lstrip(b"\x00")

    sighash = covenant_post_codesep_script.sighash(
        tx,
        input_index,
        SIGHASH_ALL,
        amount=prev_amount,
        sigversion=SIGVERSION_WITNESS_V0,
    )

    sig = rkey.sign_digest(
        sighash, k=k, sigencode=ecdsa.util.sigencode_der_canonize
    )

    # For reference: signature serialization code from secp256k1 library
    #
    # sig[0] = 0x30;
    # sig[1] = 4 + lenS + lenR;
    # sig[2] = 0x02;
    # sig[3] = lenR;
    # memcpy(sig+4, rp, lenR);
    # sig[4+lenR] = 0x02;
    # sig[5+lenR] = lenS;
    # memcpy(sig+lenR+6, sp, lenS);

    assert sig[3] == len(r)
    assert sig[4:(4 + (len(r)))] == r

    sig_prefix = sig[:4]
    sig_suffix = sig[(4 + len(r)):]

    witness_common = [
        sig_suffix,
        sig_prefix,
        sighash_preimage_data_pfx,
        struct.pack("<i", tx.nLockTime),
        other_outs_data,
    ]

    # script can contain the data explicitly, not a hash of the data
    if checked_outs_data is not None:
        witness_common.append(checked_outs_data)

    tx.wit.vtxinwit[input_index] = CElementsMutableTxInWitness(
        CScriptWitness(witness_common + witness_extra + [control_script])
    )
