import os, sys

root_path = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.abspath(root_path))
src_path = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, os.path.abspath(src_path))

import commons.config as config
from commons.constants import OptimizeMethod, OptimizeTarget
from graph_optimizer.json_manager import JsonManager, JsonPlanner
from graph_optimizer.algorithms import PipeletGroupOptimizer
from graph_optimizer.graph_optimizer import Optimizer
from graph_optimizer.control_flow_graph import ControlFlowGraph
import tests.utils as TestUtils
from commons.base_logging import LogLevel, set_log_level

import mock_import
from runtime_CLI import RuntimeAPI


def main():
    # ensure group optimization is enabled
    assert config.GROUP_CACHE_ENABLED, f"Please enable GROUP_CACHE_ENABLED in the config"
    set_log_level(LogLevel.ERROR)  # close DEBUG info
    enabled_methods = [OptimizeMethod.REORDER, OptimizeMethod.MERGE, OptimizeMethod.CACHE]

    json_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "input_data", f"group_optimization.p4.json")

    irg, target = JsonManager.retrieve_presplit(json_path)
    JsonManager.compile_time_json_planning(irg)
    ingress_graph = irg.get_pipe("ingress")
    tables = list(ingress_graph.tables)
    conds = list(ingress_graph.conditions)

    # Generate fake runtime profiles and update the statistics
    runtime_states = TestUtils.gen_runtime_stats(tables, conds, False, 0.75, 50, 150)
    optimizer = Optimizer(api=RuntimeAPI(), sampling_period_us=1000000)
    optimizer._update_pipeline_stats(irg, runtime_states)

    # Get pipelets and top-k pipelets
    pipelets = JsonPlanner.get_pipelets(ingress_graph)
    topk_pipelets = JsonPlanner.get_topk_pipelets(pipelets, 0.3, OptimizeTarget.LATENCY)

    # Get the topk group
    cfg = ControlFlowGraph._build_cfg(ingress_graph)
    ControlFlowGraph._get_aggregation(cfg)
    pipe_prgs = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelets)

    # Compute optimization based on groups
    program_option = PipeletGroupOptimizer.reoptimize_dp(
        mavail=runtime_states.total_memory,
        iavail=runtime_states.total_entry_insertion_bandwidth,
        optimize_method=enabled_methods,
        optimize_target=OptimizeTarget.LATENCY,
        pipelet_groups=pipe_prgs,
    )
    print(program_option)


if __name__ == "__main__":
    main()
