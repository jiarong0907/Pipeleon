import os, sys
from copy import deepcopy

root_path = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.abspath(root_path))
src_path = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, os.path.abspath(src_path))


from unittest.mock import patch

from commons.constants import OptimizeMethod, OptimizeTarget
import commons.config as config
from commons.base_logging import LogLevel, set_log_level
from graph_optimizer.json_manager import JsonManager, JsonDeployer, JsonPlanner
from graph_optimizer.algorithms import PipeletOptimizer
from graph_optimizer.graph_optimizer import Optimizer
import tests.utils as TestUtils

import pytest
import mock_import
from runtime_CLI import RuntimeAPI


@patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
def main(retrieve_runtime_states):

    # disable group cache for clarity
    assert config.GROUP_CACHE_ENABLED == False
    set_log_level(LogLevel.ERROR)

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
        OptimizeMethod.MERGE,
        OptimizeMethod.CACHE,
    ]

    # convert the json input to internal IR graph
    irg, target = JsonManager.retrieve_presplit(json_path)

    # compile-time planning: mark the unsupported and semi-supported tables
    JsonManager.compile_time_json_planning(irg)

    # get the ingress IR graph and all tables and conditions
    ingress_graph = irg.get_pipe("ingress")
    tables = list(ingress_graph.tables)
    conds = list(ingress_graph.conditions)

    # Generate fake runtime profile and update probability
    retrieve_runtime_states.return_value = TestUtils.gen_runtime_stats(
        tables, conds, even_counter_distr=False, drop_rate=0.25, min_tab_size=50, max_tab_size=150
    )
    json_manager = JsonManager(api=RuntimeAPI())
    runtime_states = json_manager.retrieve_runtime_states(f"{round}_presplit_preopt.json")
    optimizer = Optimizer(api=RuntimeAPI(), sampling_period_us=1000000)
    optimizer._update_pipeline_stats(irg, runtime_states)

    # get all pipelets
    pipelets = JsonPlanner.get_pipelets(ingress_graph)
    print("All pipelets: ", [tp.root.name for tp in pipelets])
    topk = 0.3
    # get the topk pipelet
    topk_pipelets = JsonPlanner.get_topk_pipelets(pipelets, topk, OptimizeTarget.LATENCY)
    print("Topk pipelets: ", [tp.root.name for tp in topk_pipelets])

    # compute the best optimization
    program_option = PipeletOptimizer.reoptimize_dp(
        mavail=runtime_states.total_memory,
        iavail=runtime_states.total_entry_insertion_bandwidth,
        optimize_method=enabled_methods,
        optimize_target=OptimizeTarget.LATENCY,
        pipelets=topk_pipelets,
    )
    assert program_option != None
    print(program_option)

    # apply the optimization and get the optimized IR
    TestUtils.apply_pipelet_options(program_option.option, ingress_graph)
    JsonDeployer.prepare_optimizer_created_tables(irg)

    # dump the optimized json
    irg.export_p4cirjson(path="optimized.json")


if __name__ == "__main__":
    main()
