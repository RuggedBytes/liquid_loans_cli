# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import hashlib
import os
from contextlib import contextmanager
from typing import (
    Callable, List, Tuple, Dict, Set, Generator, TypeVar, Optional
)

from bitcointx.core import b2x, b2lx
from bitcointx.core.key import BIP32Path, CPubKey
from bitcointx.wallet import CCoinExtKey
from elementstx.core import (
    CElementsTransaction,
    CElementsMutableTransaction,
    BlindingInputDescriptor,
    BlindingSuccess,
    CAsset,
)

import lib.types

from contextvars import ContextVar

_safe_derivation_ctx: ContextVar[Dict[str, Set[Tuple[int, ...]]]] = \
    ContextVar('safe_derivation', default=dict())


_nonexistent_dummy_type = TypeVar('_nonexistent_dummy_type')


@contextmanager
def SafeDerivation(dummy: Optional[_nonexistent_dummy_type] = None
                   ) -> Generator[None, None, None]:
    if dummy is not None:
        raise ValueError(
            'SafeDerivation context manager does not accept any arguments')

    old_seen_paths_per_key = {
        k: v.copy() for k, v in _safe_derivation_ctx.get().items()
    }
    _safe_derivation_ctx.set(dict())
    try:
        yield
    finally:
        _safe_derivation_ctx.set(old_seen_paths_per_key)


def safe_derive(xkey: CCoinExtKey, path_str: str) -> CCoinExtKey:
    """Derive the key while checking for key reuse,
    do not allow to derive from the same path with the same key twice"""

    path = tuple(BIP32Path(path_str))
    keyhash = hashlib.sha256(xkey).hexdigest()

    seen_paths = _safe_derivation_ctx.get().get(keyhash, set())

    if path in seen_paths:
        raise RuntimeError(
            f"the key {b2x(xkey.fingerprint)} was already used "
            f"with path: {path_str}"
        )
    else:
        seen_paths.add(path)
        _safe_derivation_ctx.get()[keyhash] = seen_paths

    return xkey.derive_path(path)


def make_block_cprng(seed: bytes) -> Callable[[int], bytes]:
    """Return deterministic random function that return the block data"""
    assert isinstance(seed, bytes)
    assert len(seed) == 32

    state = hashlib.sha256(seed).digest()

    def sha256_block_cprng(len: int) -> bytes:
        nonlocal state
        assert len == 32
        state = hashlib.sha256(state).digest()
        return state

    return sha256_block_cprng


def blind_tx_and_validate(
    tx: CElementsMutableTransaction,
    input_descriptors: List[BlindingInputDescriptor],
    output_pubkeys: List[CPubKey],
    _rand_func: Callable[[int], bytes] = os.urandom,
) -> BlindingSuccess:
    blind_result = tx.blind(
        input_descriptors=input_descriptors,
        output_pubkeys=output_pubkeys,
        _rand_func=_rand_func,
    )

    num_expected_to_blind = sum(1 for p in output_pubkeys if p.is_nonempty())

    # The blinding must succeed
    if blind_result.error:
        raise RuntimeError(f"blind failed: {blind_result.error}")

    assert isinstance(blind_result, BlindingSuccess)

    # And must blind exact number of outputs specified
    if blind_result.num_successfully_blinded != num_expected_to_blind:
        raise RuntimeError(
            f"blinded {blind_result.num_successfully_blinded} outputs, "
            f"expected to be {num_expected_to_blind}"
        )

    return blind_result


def find_explicit_asset_txout_index(tx: CElementsTransaction,
                                    asset: CAsset) -> int:
    for n, txout in enumerate(tx.vout):
        if txout.nAsset.is_explicit() and txout.nAsset.to_asset() == asset:
            return n
    raise lib.types.DataLookupError(
        f"tx {b2lx(tx.GetTxid())} must have an output"
        f" with explicit asset {asset}"
    )
