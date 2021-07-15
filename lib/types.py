# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import hashlib
import json
import os
import abc
import time
from urllib.parse import urlparse
from decimal import Decimal, DecimalException
from io import BytesIO, StringIO
from math import floor
from typing import Callable, List, Optional, Tuple, Union, Any

import click
from attr import asdict, attrib, attrs, validators
from attr.validators import instance_of
from bitcointx.core import b2x, coins_to_satoshi, lx, satoshi_to_coins, Uint256
from bitcointx.core.key import CKey, CPubKey
from bitcointx.core.script import MAX_SCRIPT_ELEMENT_SIZE, CScript
from bitcointx.rpc import RPCCaller
from bitcointx.wallet import CCoinAddress, CCoinExtKey
from elementstx.wallet import CCoinConfidentialAddress
from elementstx.core import (
    BlindingInputDescriptor,
    CAsset,
    CElementsMutableTransaction,
    CElementsTransaction,
    CElementsOutPoint,
)

from .constants import (
    RANDOM_BYTES_PER_BLINDING_FACTORS,
    RANDOM_BYTES_PER_UNIT_BLINDING,
    MIN_GUARANTEED_CHANGE
)
from .utils import make_block_cprng, safe_derive

try:
    from rich.console import Console

    use_rich_prettyprint = True
except ImportError:
    use_rich_prettyprint = False


def _format_amount(value: int, digit_position: int) -> str:
    value_frac = Decimal(value) / Decimal(10 ** digit_position)
    return f"{value_frac}"


class ElementsRPCCaller:
    def __init__(self, **kwargs: Any) -> None:
        self._coin_api = RPCCaller(**kwargs)
        self._last_use_time = time.time()

    def __getattr__(self, name: str) -> Callable[..., Any]:
        now = time.time()
        diff = now - self._last_use_time

        # if 5 seconds passed since last call, close the connection
        # and re-connect. Since we're not reconnecting on failures during
        # the call, this is safe, no way to double-tap wallet API calls
        if diff < 0 or diff > 5:
            self._coin_api.close()
            self._coin_api.connect()

        self._last_use_time = now

        return self._coin_api.__getattr__(name)


class Amount(int):
    """Amount type in satoshies"""

    def __new__(cls, value: Union[int, str, Decimal]) -> "Amount":
        def MakeAmount(value: Union[int, str]) -> Amount:
            value = super(Amount, cls).__new__(cls, value)
            if value < 0:
                ValueError("value must be greater than zero")
            return value

        if isinstance(value, (int, str)):
            return MakeAmount(value)
        elif isinstance(value, Decimal):
            return MakeAmount(coins_to_satoshi(value))
        raise ValueError(f"type {type(value)} of value not supported")

    @property
    def coins(self) -> Decimal:
        return satoshi_to_coins(self)


def decimal_cnv(value: Any) -> Decimal:
    """Decimal converter"""

    if isinstance(value, Decimal):
        return value

    if isinstance(value, (str, int)):
        return Decimal(value)

    raise TypeError(
        f'expected str or int value, got value of type {type(value)}')


def decimal_lst_cnv(values: Any) -> List[Decimal]:
    return list(map(decimal_cnv, values))


def asset_cnv(value: Any) -> CAsset:
    """Asset converter"""

    if isinstance(value, CAsset):
        return value

    if isinstance(value, str):
        return CAsset(lx(value))

    raise TypeError('expected string value')


def rates_cnv(value: Any) -> 'Rates':
    """Rates converter"""

    if isinstance(value, Rates):
        return value

    if isinstance(value, dict):
        return Rates(rate_due=value['rate_due'],
                     rate_early=value['rate_early'],
                     rate_collateral_penalty=value['rate_collateral_penalty'],
                     rates_late=value['rates_late'])

    raise TypeError('expected dict value')


@attrs(auto_attribs=True)
class AssetAmount:
    asset: CAsset = attrib(converter=asset_cnv, validator=instance_of(CAsset))
    amount: Amount = attrib(converter=Amount, validator=instance_of(Amount))


@attrs(auto_attribs=True)
class Rates:
    rate_due: Decimal = attrib(
        converter=decimal_cnv, validator=instance_of(Decimal)
    )
    rate_early: Decimal = attrib(
        converter=decimal_cnv, validator=instance_of(Decimal)
    )
    rate_collateral_penalty: Decimal = attrib(
        converter=decimal_cnv, validator=instance_of(Decimal)
    )
    rates_late: List[Decimal] = attrib(
        converter=decimal_lst_cnv,
        validator=validators.deep_iterable(
            member_validator=instance_of(Decimal),
            iterable_validator=instance_of(list),
        ),
    )

    def deterministic_representation(self) -> bytes:
        return str(
            (
                self.rate_due.as_integer_ratio(),
                self.rate_early.as_integer_ratio(),
                self.rate_collateral_penalty.as_integer_ratio(),
                tuple(
                    rl.as_integer_ratio() for rl in
                    self.rates_late
                ),
            )
        ).encode("ascii")


@attrs(auto_attribs=True)
class BlindingInfo:
    descriptors: List[BlindingInputDescriptor]
    pubkeys: List[CPubKey]


class LoanInfo(abc.ABC):

    value_blinding_factor: Uint256
    asset_blinding_factor: Uint256

    def __init__(self, *, tx: CElementsTransaction, vout_index: int,
                 blinding_key: CKey, control_addr: CCoinConfidentialAddress,
                 plan: 'RepaymentPlan'
                 ) -> None:
        if vout_index < 0 or vout_index >= len(tx.vout):
            raise ValueError('vout_index is out of range')
        self.tx = tx
        self.vout_index = vout_index
        self.blinding_key = blinding_key
        self.control_addr = control_addr

        self._unblind_and_check(plan)

    def _unblind_and_check(self, plan: 'RepaymentPlan') -> None:

        asset: CAsset
        amount: Amount

        if isinstance(self, DebtorLoanStartInfo):
            asset = plan.collateral.asset
            amount = plan.collateral.amount
        elif isinstance(self, CreditorLoanStartInfo):
            asset = plan.principal.asset
            amount = plan.principal.amount
        else:
            raise TypeError(
                'only DebtorLoanStartInfo or CreditorLoanStartInfo is handled')

        if self.vout_index >= len(self.tx.vout):
            raise ValueError("vout_index is incorrect, exceeds tx.vout")

        unblind_result = \
            self.tx.vout[self.vout_index].unblind_confidential_pair(
                self.blinding_key,
                self.tx.wit.vtxoutwit[self.vout_index].rangeproof
            )

        if unblind_result.error:
            raise ValueError(
                f"cannot unblind asset output:" f" {unblind_result.error}"
            )

        if unblind_result.asset != asset:
            raise ValueError(
                f"the unblinded asset ("
                f"{unblind_result.asset.to_hex()}) "
                f"in asset output does not match the expected asset "
                f"({asset.to_hex()})"
            )

        if unblind_result.amount < amount:
            raise ValueError(
                f"the expected amount ({amount})"
                f" is less than unblinded asset amount in asset"
                f"({unblind_result.amount})"
            )

        self.value_blinding_factor = unblind_result.blinding_factor
        self.asset_blinding_factor = unblind_result.asset_blinding_factor
        self.set_amount(unblind_result.amount)

    @abc.abstractmethod
    def set_amount(self, amount: int) -> None:
        ...

    def to_json(self) -> str:
        class DecimalJSONEncoder(json.JSONEncoder):
            def default(self, o: Any) -> str:
                if isinstance(o, CCoinAddress):
                    return f"{o}"
                elif isinstance(o, CElementsTransaction):
                    return b2x(o.serialize())
                elif isinstance(o, CKey):
                    return b2x(o.secret_bytes)
                val = super().default(o)
                assert isinstance(val, str)
                return val

        mydict = asdict(self)
        return json.dumps(mydict, cls=DecimalJSONEncoder, indent=4)


class DebtorLoanStartInfo(LoanInfo):
    def __init__(self, *, receive_addr: CCoinConfidentialAddress,
                 collateral_change_addr: CCoinConfidentialAddress,
                 **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.receive_addr = receive_addr
        self.collateral_change_addr = collateral_change_addr

    def set_amount(self, amount: int) -> None:
        self.collateral_amount = amount


class CreditorLoanStartInfo(LoanInfo):
    def __init__(self, *, principal_change_addr: CCoinConfidentialAddress,
                 **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.principal_change_addr = principal_change_addr

    def set_amount(self, amount: int) -> None:
        self.principal_amount = amount


@attrs(auto_attribs=True)
class PlanData:
    principal_asset: CAsset = attrib(
        converter=asset_cnv, validator=instance_of(CAsset)
    )
    principal_amount: int
    collateral_asset: CAsset = attrib(
        converter=asset_cnv, validator=instance_of(CAsset)
    )
    collateral_amount: int
    # amount of collateral that is unconditionally forfeited in the
    # event of debtor's default
    amount_C_uncond: int
    N: int
    S: int
    num_blocks_in_period: int

    rates: 'Rates' = attrib(
        converter=rates_cnv, validator=instance_of(Rates)
    )

    def to_json(self) -> str:
        class DecimalJSONEncoder(json.JSONEncoder):
            def default(self, o: Any) -> str:
                if isinstance(o, Decimal):
                    r = float(o)
                    if f"{r:.08f}" != f"{o:.08f}":
                        raise TypeError(
                            f"value {o!r} lost precision beyond"
                            f" acceptable range "
                            f"when converted to float: {r:.08f} != {o:.08f}"
                        )
                    return f"{r}"
                elif isinstance(o, CAsset):
                    return o.to_hex()
                val = super().default(o)
                assert isinstance(val, str)
                return val

        mydict = asdict(self)
        return json.dumps(mydict, cls=DecimalJSONEncoder, indent=4)

    def to_repayment_plan(self, min_output: int = 1) -> 'RepaymentPlan':
        return RepaymentPlan(
            rates=self.rates,
            principal=AssetAmount(self.principal_asset, self.principal_amount),
            collateral=AssetAmount(self.collateral_asset,
                                   self.collateral_amount),
            N=self.N,
            S=self.S,
            num_blocks_in_period=self.num_blocks_in_period,
            min_output=min_output,
            amount_C_uncond=self.amount_C_uncond
        )


class BlindedInputInfo:
    def __init__(self,
                 outpoint: CElementsOutPoint,
                 blinding_input_descriptor: BlindingInputDescriptor
                 ) -> None:
        self.outpoint = outpoint
        self.blinding_input_descriptor = blinding_input_descriptor


class RPCPathParamType(click.ParamType):
    """RPC daemon type"""

    name = "Config RPC"

    def convert(self, value: Any, param: Any, ctx: Any) -> ElementsRPCCaller:
        parse_r = urlparse(value)
        try:
            if parse_r.scheme:
                return ElementsRPCCaller(service_url=value)
            else:
                return ElementsRPCCaller(conf_file=value)
        except Exception as e:
            self.fail(f"Exception: {e}")


class BlockchainNetworkType(click.ParamType):

    name = "Blockchain Network"

    def convert(self, value: Any, param: Any, ctx: Any) -> str:
        allowed_networks = {"elements": "elements",
                            "liquidv1": "elements/liquidv1"}

        if value not in allowed_networks.keys():
            self.fail(
                f"allowed values for blockchain network option: "
                f"{list(allowed_networks.keys())}")

        return allowed_networks[value]


class AmountParamType(click.ParamType):

    name = "Amount"

    def convert(self, value: Any, param: Any, ctx: Any) -> Amount:
        if not isinstance(value, (int, str)):
            self.fail(f"{value!r} is not of type str or int")

        try:
            return Amount(value)
        except ValueError:
            self.fail(f"{value!r} is not a valid amount")


class AssetParamType(click.ParamType):

    name = "Asset"

    def convert(self, value: Any, param: Any, ctx: Any) -> CAsset:
        try:
            return CAsset(lx(value))
        except Exception as e:
            self.fail(f"{value!r} is not a valid asset type: {e}")


class RepaymentPlan:

    first_lateral_stage: 'LateralProgressionStage'

    def __init__(
        self,
        *,
        S: int,
        N: int,
        rates: Rates,
        principal: AssetAmount,
        collateral: AssetAmount,
        amount_C_uncond: int,
        num_blocks_in_period: int,
        min_output: int = MIN_GUARANTEED_CHANGE
    ):
        assert principal.amount > 0, "principal amount is excepted be > 0"
        assert collateral.amount > 0, "collateral amount is excepted be > 0"
        assert amount_C_uncond <= collateral.amount, \
            ("collateral unconditional forfeiture amount is excepted be "
             "less or equal to the collateral amount")

        self.N = N
        self.S = S
        self.principal = principal
        self.collateral = collateral
        self.amount_C_uncond = amount_C_uncond
        self.rates = rates
        self.num_blocks_in_period = num_blocks_in_period

        assert self.M >= 0

        # "The contract ends in maximum S \in [max{N,M}+1,N+M] number of steps"
        assert (max(self.N, self.M)+1 <= self.S <= self.N + self.M), \
            f"N={self.N}, M={self.M}, S={self.S}, RL: {self.rates.rates_late}"

        self.first_lateral_stage = LateralProgressionStage.generate_tree(
            plan=self, B=self.P,
            min_output=min_output
        )

    @property
    def P(self) -> int:
        return self.principal.amount

    @property
    def C(self) -> int:
        return self.collateral.amount

    @property
    def M(self) -> int:
        return len(self.rates.rates_late)+1

    @property
    def frac_P(self) -> int:
        """'Fraction of P' is the installment size"""
        amount_for_period = self.P // self.N
        assert amount_for_period > 0
        return amount_for_period

    @property
    def P_remainder(self) -> int:
        r = self.P % self.N
        assert self.P == self.frac_P * self.N + r
        return r

    def deterministic_representation(self) -> bytes:
        return str(
            (
                self.N,
                self.principal.asset.to_hex(),
                self.P,
                self.collateral.asset.to_hex(),
                self.C,
                self.rates.deterministic_representation(),
            )
        ).encode("ascii")

    def get_derivation_path_for_blinding_key(self) -> str:
        plan_hash = hashlib.sha256(
            self.deterministic_representation()
        ).digest()
        high_bits_accum = 0
        indexes = []
        for i in range(4):
            indexes.append(
                (plan_hash[i * 4] & 0x7F) * (2 ** 24)
                + plan_hash[i * 4 + 1] * (2 ** 16)
                + plan_hash[i * 4 + 2] * (2 ** 8)
                + plan_hash[i * 4 + 3]
            )
            high_bits_accum += int(bool(plan_hash[i * 4] & 0x80)) * (1 << i)

        indexes.append(high_bits_accum)

        return "/".join(f"{i}h" for i in indexes)

    def pretty_format(
        self, is_full: bool = False, debt_digits: int = 2, coll_digits: int = 8
    ) -> str:
        return self.first_lateral_stage.pretty_format(
            is_full, debt_digits, coll_digits
        )


class LateralProgressionStage:
    def __init__(
        self,
        *,
        B: int,
        level_n: int,
        total_repaid: int,
        path: str = "",
        plan: RepaymentPlan,
        vertical_stages: List["VerticalProgressionStage"],
    ):
        self.B = B
        self.level_n = level_n
        self.total_repaid = total_repaid
        self.path = path
        self.plan = plan
        self.vertical_stages = vertical_stages

    @classmethod
    def generate_tree(
        cls,
        *,
        B: int,
        plan: RepaymentPlan,
        level_n: int = 0,
        total_repaid: int = 0,
        min_output: int = MIN_GUARANTEED_CHANGE,
        path: str = ""
    ) -> 'LateralProgressionStage':

        vertical_stages: List[VerticalProgressionStage] = []

        lstage = cls(B=B, level_n=level_n, total_repaid=total_repaid,
                     path=path, plan=plan, vertical_stages=vertical_stages)

        # From the spec:
        #
        # "Before each t_s,s \in [1,S−1] Alice will receive A_reg, and then:"
        #
        # "m will be reset to 0"
        for index_m in range(plan.M):
            vstage = VerticalProgressionStage(index_m, lstage)
            # "B will be decreased by D"
            next_B = B - vstage.D
            # "n will be incremented"
            next_level_n = level_n + 1

            if vstage.regular_repayment_amount < min_output:
                raise CheckOutputError(
                    f"regular payment amount {vstage.regular_repayment_amount}"
                    f" is below minimum output {min_output}"
                )

            if vstage.early_repayment_amount > vstage.regular_repayment_amount:
                new_total_repaid = \
                    total_repaid + vstage.regular_repayment_amount

                vstage.next_lateral_stage = cls.generate_tree(
                    B=next_B, level_n=next_level_n,
                    total_repaid=new_total_repaid,
                    min_output=min_output,
                    path=f"{path}>",
                    plan=plan
                )

            lstage.vertical_stages.append(vstage)

            # The length of the vstage array is limited by the following
            # lines in the spec:
            #
            # "Otherwise, m will be incremented.
            #  If m >= M, or after t_s, s >= S−1,
            #  Alice will be able to claim certain portion of C"
            #
            # "m >= M" corresponds to this loop going over range(plan.M).
            #
            # "after t_s, s >= S−1" is handled by the following lines:
            s = level_n + index_m

            if s >= plan.S - 1:
                break

            path = f"{path}v"

        return lstage

    def pretty_format(
        self, is_full: bool = False, debt_digits: int = 2, coll_digits: int = 8
    ) -> str:
        console: Optional[Console]
        if use_rich_prettyprint:
            console = Console(file=StringIO(), force_terminal=True)
            arrow_right = ':arrow_right:'
        else:
            console = None
            arrow_right = '`->'

        if self.level_n and is_full:
            prefix = (" " * (self.level_n - 1) * 4) + arrow_right
        else:
            prefix = ""

        line = f"{prefix} body={_format_amount(self.B, debt_digits)}\n"

        if use_rich_prettyprint:
            console.print(line)
            result = [console.file.getvalue()]
        else:
            result = [line]

        result += "".join(vs.pretty_format(is_full=is_full)
                          for vs in self.vertical_stages)

        return "".join(result)


class VerticalProgressionStageBlindingData:
    def __init__(self,
                 blinding_xkey: CCoinExtKey,
                 contract_input_descriptor: BlindingInputDescriptor
                 ) -> None:
        self.blinding_xkey = blinding_xkey
        self.contract_input_descriptor = contract_input_descriptor


class VerticalProgressionStageScriptData:
    def __init__(self, script: CScript, checked_outs_hashes: bytes) -> None:
        self.script = script
        self.checked_outs_hashes = checked_outs_hashes


class VerticalProgressionStage:

    blinding_data: VerticalProgressionStageBlindingData
    script_data: VerticalProgressionStageScriptData
    next_lateral_stage: Optional[LateralProgressionStage]

    def __init__(
        self,
        index_m: int,
        parent_lateral_stage: LateralProgressionStage
    ):
        self.index_m = index_m
        self.parent_lateral_stage = parent_lateral_stage

        self.next_lateral_stage = None

    @property
    def plan(self) -> RepaymentPlan:
        return self.parent_lateral_stage.plan

    @property
    def B(self) -> int:
        return self.parent_lateral_stage.B

    def balance_portion(self, m: int) -> int:

        v = self.plan.frac_P * m

        # TLA spec: LimitByBalance
        if v + self.plan.P_remainder >= self.B:
            return self.B
        else:
            return v

    @property
    def D(self) -> int:
        return self.balance_portion(self.index_m + 1)

    @property
    def L(self) -> int:
        return self.balance_portion(self.index_m)

    @staticmethod
    def apply_rate(v: int, r: Decimal) -> int:
        return int(floor(v * (r / Decimal("100"))))

    def apply_late_rate(self, v: int, rn: int) -> int:
        if rn == 0:
            return 0
        return self.apply_rate(v, self.plan.rates.rates_late[rn-1])

    @property
    def regular_repayment_amount(self) -> int:
        return (
            self.D
            + self.apply_rate(self.B, self.plan.rates.rate_due)
            + self.apply_late_rate(self.L, self.index_m)
        )

    @property
    def early_repayment_amount(self) -> int:
        return (
            self.B
            + self.apply_rate(self.B, self.plan.rates.rate_due)
            + self.apply_rate((self.B - self.D), self.plan.rates.rate_early)
            + self.apply_late_rate(self.L, self.index_m)
        )

    @property
    def full_repayment_amount(self) -> int:
        if self.early_repayment_amount > self.regular_repayment_amount:
            assert self.next_lateral_stage is not None
            return self.early_repayment_amount
        else:
            assert (self.regular_repayment_amount
                    == self.early_repayment_amount)
            return self.regular_repayment_amount

    @property
    def amount_for_collateral_forfeiture_penalty(self) -> int:
        """Principal amount used in the amount_C_forfeited calculation"""
        amount = max(self.B, self.regular_repayment_amount)
        return (
            amount
            + self.apply_rate(amount, self.plan.rates.rate_collateral_penalty)
        )

    @property
    def amount_C_forfeited(self) -> int:
        """Collateral amount to be forfeited on debtor's default"""
        penalty_amount = self.amount_for_collateral_forfeiture_penalty
        return max(
            self.plan.amount_C_uncond,
            min(self.plan.C, (self.plan.C * penalty_amount) // self.plan.P)
        )

    @property
    def branch_contract_entropy(self) -> Optional[bytes]:
        if self.next_lateral_stage is not None:
            branch_vstage = self.next_lateral_stage.vertical_stages[0]
            cid = branch_vstage.blinding_data.contract_input_descriptor
            assert cid is not None
            return bytes(
                cid.blinding_factor.data + cid.asset_blinding_factor.data
            )

        return None

    def build_deterministic_random_generator(
        self,
        path: str,
        *,
        num_special_blindings: int,
        contract_entropy: Optional[bytes] = None,
    ) -> Callable[[int], bytes]:
        cprng_seed = hashlib.sha256(
            safe_derive(self.blinding_data.blinding_xkey, path)
        ).digest()
        block_cprng = make_block_cprng(cprng_seed)

        random_consumed = 0

        assert (
            contract_entropy is None
            or len(contract_entropy) == 64
        )

        def deterministic_random_generator(len: int) -> bytes:
            nonlocal random_consumed
            assert len == 32

            if contract_entropy is not None:
                if random_consumed < RANDOM_BYTES_PER_BLINDING_FACTORS:
                    random_consumed += 32
                    return contract_entropy[
                        (random_consumed - 32):random_consumed
                    ]

            if random_consumed < \
                    RANDOM_BYTES_PER_UNIT_BLINDING * num_special_blindings:
                random_consumed += 32
                return block_cprng(len)

            # Random data for outputs not bound by the contract
            # needs to be unpredictable
            return os.urandom(len)

        return deterministic_random_generator

    def num_vstages_recursive(self, *, only_branched: bool) -> int:
        if self.next_lateral_stage is None:
            return 0 if only_branched else 1
        return sum(vs.num_vstages_recursive(only_branched=only_branched)
                   for vs in self.next_lateral_stage.vertical_stages) + 1

    def pretty_format(
        self, is_full: bool = False, debt_digits: int = 2, coll_digits: int = 8
    ) -> str:
        console: Optional[Console]

        if use_rich_prettyprint:
            console = Console(file=StringIO(), force_terminal=True)
        else:
            console = None

        def fmt_amt(value: int) -> str:
            return _format_amount(value, debt_digits)

        level_n = self.parent_lateral_stage.level_n
        if is_full:
            prefix = " " * (level_n * 4)
        else:
            prefix = f"({self.index_m}/{level_n}) "

        result = [prefix]

        if self.next_lateral_stage:
            amount_str = _format_amount(self.regular_repayment_amount,
                                        debt_digits)
            result.append(f"{amount_str} | ")

        result += [f"{fmt_amt(self.early_repayment_amount)} -> []"]

        if is_full:
            late_amount = self.plan.frac_P * self.index_m
            left = self.B - late_amount - self.plan.frac_P
            if self.index_m == 0:
                rate_late = Decimal("0")
            else:
                rate_late = self.plan.rates.rates_late[self.index_m-1]

            if self.next_lateral_stage:
                result += [
                    f"  # {fmt_amt(late_amount)}+{rate_late}% +"
                    f" {fmt_amt(self.plan.frac_P)}"
                    f"+{self.plan.rates.rate_due}%"
                    f" | {fmt_amt(late_amount)}+{rate_late}% +"
                    f" {fmt_amt(self.plan.frac_P)}"
                    f"+{self.plan.rates.rate_due}% +{fmt_amt(left)}"
                    f"+{self.plan.rates.rate_early}%"
                ]
            else:
                result += [
                    f"  # "
                    f"{fmt_amt(left)}"
                    f"+{rate_late}%+{self.plan.rates.rate_due}%"
                ]

            if use_rich_prettyprint:
                console.print("".join(result))
                result = [console.file.getvalue()]

            if self.next_lateral_stage:
                result.append("\n")
                result.append(
                    self.next_lateral_stage.pretty_format(is_full=is_full))
        else:
            if use_rich_prettyprint:
                console.print("".join(result))
                result = [console.file.getvalue()]

        return "".join(result)


class ContractTransaction(CElementsTransaction):
    block_num: int


class ContractMutableTransaction(  # type: ignore
    ContractTransaction,
    CElementsMutableTransaction,
    mutable_of=ContractTransaction,
):

    NUM_NONFIXED_OUTS = 3

    @property
    def checked_outs_data(self) -> bytes:
        return self.split_outs_data()[0]

    @property
    def other_outs_data(self) -> bytes:
        return self.split_outs_data()[1]

    def split_outs_data(self) -> Tuple[bytes, bytes]:
        """Split the transaction onto checked and unchecked parts"""
        assert len(self.vout) >= 3, "Must be 3 or more outputs for splitting"
        b_io = BytesIO()
        self.vout[-self.NUM_NONFIXED_OUTS].nAsset.stream_serialize(b_io)
        self.vout[-self.NUM_NONFIXED_OUTS].nValue.stream_serialize(b_io)
        self.vout[-self.NUM_NONFIXED_OUTS].nNonce.stream_serialize(b_io)
        partial_txout_data = bytes(b_io.getbuffer())
        checked_outs_data = (
            b"".join(
                txout.serialize()
                for txout in self.vout[: -self.NUM_NONFIXED_OUTS]
            )
            + partial_txout_data
        )
        other_outs_data = self.vout[-self.NUM_NONFIXED_OUTS].serialize()[
            len(partial_txout_data):
        ] + b"".join(
            txout.serialize()
            for txout in self.vout[(-self.NUM_NONFIXED_OUTS + 1):]
        )

        # make sure outs data will fit into MAX_SCRIPT_ELEMENT_SIZE
        full_outs_data = b"".join(txout.serialize() for txout in self.vout)
        assert len(full_outs_data) <= MAX_SCRIPT_ELEMENT_SIZE, len(
            full_outs_data
        )
        return checked_outs_data, other_outs_data


class CheckOutputError(Exception):
    def __init__(self, message: str) -> None:
        self.message = message


class DataLookupError(Exception):
    def __init__(self, message: str) -> None:
        self.message = message


class CreditorAsset(CAsset):
    ...


class DebtorAsset(CAsset):
    ...


class BitcoinAsset(CAsset):
    ...


class RateListOption(click.Option):

    def type_cast_value(self, ctx: Any, value: str) -> Tuple[Decimal, ...]:
        rvs = []
        if value:
            for rv in value.split(','):
                if not (rv[0].isdigit() and rv[-1].isdigit()):
                    raise click.BadParameter(value)
                try:
                    rvs.append(Decimal(rv))
                except DecimalException:
                    raise click.BadParameter(value)

        return tuple(rvs)
