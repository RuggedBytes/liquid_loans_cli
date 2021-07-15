# Copyright (c) 2020-2021 Rugged Bytes IT-Services GmbH
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.


def test_pretty_print(participants_data, capsys):  # type: ignore
    plandata = participants_data.plan
    repayment_plan = plandata.to_repayment_plan()

    with capsys.disabled():
        print(repayment_plan.pretty_format(is_full=True))
