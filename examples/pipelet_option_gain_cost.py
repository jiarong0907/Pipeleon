import os, sys, csv
from typing import List
from unittest.mock import patch

root_path = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.abspath(root_path))
src_path = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, os.path.abspath(src_path))

from commons.constants import OptimizeMethod

from unittest.mock import patch


import commons.config as config
from graph_optimizer.json_manager import JsonManager, JsonPlanner
from graph_optimizer.algorithms import PipeletOptimizer
from graph_optimizer.graph_optimizer import Optimizer
from graph_optimizer.options import PipeletOption
import tests.utils as TestUtils

import pytest
import mock_import
from runtime_CLI import RuntimeAPI


@patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
def option_gain_cost_with_random_input(json_path, enabled_methods, output_path, retrieve_runtime_states) -> None:
    """Optimize a given P4 program with fake random runtime profile. Save the
    performance gain of each pipelet option into a cvs file.
    """

    # disable group cache for clarity
    assert not config.GROUP_CACHE_ENABLED

    # convert the json input to internal IR graph
    irg, target = JsonManager.retrieve_presplit(json_path)

    # compile-time planning: mark the unsupported and semi-supported tables
    JsonManager.compile_time_json_planning(irg)

    # get the ingress IR graph and all tables and conditions
    ingress_graph = irg.get_pipe("ingress")
    tables = list(ingress_graph.tables)
    conds = list(ingress_graph.conditions)

    # Generate fake runtime profile and update probability
    retrieve_runtime_states.return_value = TestUtils.gen_runtime_stats_random(tables, conds)
    json_manager = JsonManager(api=RuntimeAPI())
    runtime_states = json_manager.retrieve_runtime_states(f"{round}_presplit_preopt.json")
    optimizer = Optimizer(api=RuntimeAPI(), sampling_period_us=1000000)
    optimizer._update_pipeline_stats(irg, runtime_states)

    # Compute all optimization options
    pipelets = JsonPlanner.get_pipelets(ingress_graph)
    pipelet_options: List[List[PipeletOption]] = []
    for pipelet in pipelets:
        options = PipeletOptimizer._compute_all_options(pipelet, enabled_methods)
        pipelet_options.append(options)

    # retrieve and save the result
    info_list = []
    for pipelet_option in pipelet_options:
        for option in pipelet_option:
            # print the optimization option information
            print(option.info())
            info_list.append(option.info())

    keys = info_list[0].keys()
    with open(output_path, "w", newline="") as output_file:
        dict_writer = csv.DictWriter(output_file, keys)
        dict_writer.writeheader()
        dict_writer.writerows(info_list)


def main():
    # input json
    json_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "..",
        "tests",
        "testdata",
        "simple_dash",
        "test.p4.json",
    )

    # enabled optimization methods
    enabled_methods = [
        OptimizeMethod.REORDER,
        OptimizeMethod.SOFTCOPY,
        OptimizeMethod.SOFTMOVE,
        OptimizeMethod.MERGE,
        OptimizeMethod.CACHE,
    ]

    # output csv file
    output_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "options.csv")
    option_gain_cost_with_random_input(json_path, enabled_methods, output_path)


if __name__ == "__main__":
    main()
