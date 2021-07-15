#!/usr/bin/env python3

# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import json
import os
from pathlib import Path
from subprocess import PIPE, run

import click


def createdatafromconfig(config, tla2tools, spec, output):  # type: ignore
    suffix = "_".join(
        str(val)
        for val in [
            config["principal"],
            config["collateral"],
            config["num_periods"],
            config["num_skips"],
            config["rate_due"],
            config["rate_early"],
            config["collateral_penalty"],
            *config["rates_late"],
        ]
    )
    spec = Path(spec)

    MC_file = str(spec / f"MC_{suffix}.tla")
    output = Path(output)
    if not output.exists():
        output.mkdir(parents=True, exist_ok=True)
    output_file = str(output / suffix)
    with click.open_file(MC_file, "w") as f:
        f.write(
            f"""---- MODULE MC_{suffix} ----
EXTENDS ABL_with_partial_repayments, TLC, Logging

const_P == {config["principal"]}
const_C == {config["collateral"]}
const_N == {config["num_periods"]}
const_M == {config["num_skips"]}
const_RateDue == {config["rate_due"]}
const_RateEarly == {config["rate_early"]}
const_RateCollateralPenalty == {config["collateral_penalty"]}
const_RatesLate == <<{", ".join(str(val) for val in config["rates_late"])}>>
{"const_S == Max({const_N, const_M})+1"
if config["equilateral"] else "const_S == const_N + const_M"}
const_BLOCKS_IN_PERIOD == 4
const_START_BLOCK == 1
const_C_UNCOND == 1


=============================================================================

            """
        )
    metadir = spec / "metadir"
    if not metadir.exists():
        metadir.mkdir(parents=True, exist_ok=True)
    args = [
        "java",
        "-jar",
        str(tla2tools),
        "-config",
        "ABL_with_partial_repayments.cfg",
        "-workers",
        "1",
        "-metadir",
        str(metadir),
        "-terse",
        "-cleanup",
        "-deadlock",
        str(MC_file),
    ]
    tla2 = run(args, stdout=PIPE, cwd=str(spec),)
    with click.open_file(output_file, "wb") as f:
        f.write(tla2.stdout)


@click.command()
@click.option(
    "--cfg",
    "cfg",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True,),
    default="/".join([os.getcwd(), "plan_variants_to_validate.json"]),  # type: ignore
    help="path to the file that contains plan variants",
    show_default=True,
    required=True,
)
@click.option(
    "--tla2tools",
    "tla2tools",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True,),
    help="path to the tla2tools.jar",
    required=True,
)
@click.option(
    "--spec",
    "spec",
    type=click.Path(exists=True, dir_okay=True, resolve_path=True,),
    help="path to the dir that contains tla2 spec files",
    required=True,
)
@click.option(
    "--output",
    "output",
    type=click.Path(exists=False, dir_okay=True, resolve_path=True,),
    default="/".join([os.getcwd(), "tests", "data"]),
    help="path to the dir where the testdata will be generated",
    show_default=True,
)
def generatedata(cfg, tla2tools, spec, output):
    with click.open_file(cfg) as f:
        configs = json.loads(f.read())
    with click.progressbar(configs) as bar:
        for config in bar:
            createdatafromconfig(config, tla2tools, spec, output)  # type: ignore


if __name__ == "__main__":
    generatedata()
