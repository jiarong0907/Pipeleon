from copy import deepcopy
import os, sys
import pickle
import time
from typing import Dict, List, Optional, Tuple

root_path = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.abspath(root_path))
src_path = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, os.path.abspath(src_path))

import commons.config as config
from commons.constants import OptimizeMethod, OptimizeTarget
from commons.metric import ProgramEvalMetric
from commons.types import TableName
from graph_optimizer.json_manager import JsonManager, JsonPlanner
from graph_optimizer.pipelet import Pipelet, PipeletGroup
from graph_optimizer.algorithms import PipeletOptimizer
from graph_optimizer.graph_optimizer import Optimizer
from graph_optimizer.control_flow_graph import ControlFlowGraph
from graph_optimizer.options import (
    AggregatedOption,
    GroupCacheOption,
    GroupMergeOption,
    PipeletGroupOption,
    PipeletOption,
    ProgramOption,
    SegmentOptimizationOption,
)
from ir.irgraph import IrGraph
from ir.irgraph_pipe import IrGraphPipe
from commons.base_logging import LogLevel, set_log_level

import tests.mock_import
from runtime_CLI import RuntimeAPI


def load_graph_from_json(json_path) -> Tuple[IrGraph, IrGraphPipe]:
    irg, target = JsonManager.retrieve_presplit(json_path)
    JsonManager.compile_time_json_planning(irg)
    ingress_graph = irg.get_pipe("ingress")
    return irg, ingress_graph


def topk_gain_and_time_with_runtime_stats(
    json_path, topk: float, enabled_methods, runtime_states
) -> Tuple[Optional[ProgramEvalMetric], float]:
    """Optimize a given P4 program with fake runtime profile. Return the
    performance gain and optimization time.
    """
    assert not config.GROUP_CACHE_ENABLED

    irg, ingress_graph = load_graph_from_json(json_path)

    optimizer = Optimizer(api=RuntimeAPI(), sampling_period_us=1000000)
    optimizer._update_pipeline_stats(irg, runtime_states)

    pipelets = JsonPlanner.get_pipelets(ingress_graph)
    topk_pipelets = JsonPlanner.get_topk_pipelets(pipelets, topk, OptimizeTarget.LATENCY)

    start = time.time()
    program_option = PipeletOptimizer.reoptimize_dp(
        mavail=runtime_states.total_memory,
        iavail=runtime_states.total_entry_insertion_bandwidth,
        optimize_method=enabled_methods,
        optimize_target=OptimizeTarget.LATENCY,
        pipelets=topk_pipelets,
    )
    end = time.time()

    if program_option is None:
        return None, round(end - start, 3)
    else:
        return eval_program(program_option), round(end - start, 3)


def apply_pipelet_options(options: List[AggregatedOption], irgraph_pipe: IrGraphPipe):
    """Apply the whole program optimization to a copied graph. Used to
    evaluate the performance gain.
    """
    pipelets_copy = JsonPlanner.get_pipelets(irgraph_pipe)
    root_name_to_pipelet: Dict[TableName, Pipelet] = {}
    for pipelet in pipelets_copy:
        root_name_to_pipelet[pipelet.root.name] = pipelet

    for op in options:
        assert isinstance(op, PipeletOption), f"The option is not PipeletOption. Got type{op}"
        JsonPlanner.apply_reordering(root_name_to_pipelet[op.pipelet.root.name], op.new_order)
        # only the reorder option
        if op.combined_options == None:
            return
        for comb_op in op.combined_options:
            if isinstance(comb_op, SegmentOptimizationOption):
                JsonPlanner.apply_segment_opt(root_name_to_pipelet[op.pipelet.root.name], comb_op)
            else:
                raise Exception("Unrecognized optimization option!")


def apply_pipelet_group_options(
    options: List[AggregatedOption], irgraph_pipe: IrGraphPipe, topk_pipelets: List[Pipelet]
) -> None:
    """Apply the whole program optimization to a copied graph. Used to
    evaluate the performance gain.
    """
    # Need to rebuild the pipelet group on the copied graph
    cfg = ControlFlowGraph._build_cfg(irgraph_pipe)
    ControlFlowGraph._get_aggregation(cfg)
    pipelets_copy = JsonPlanner.get_pipelets(irgraph_pipe)
    root_name_to_pipelet: Dict[TableName, Pipelet] = {}
    for pipelet in pipelets_copy:
        root_name_to_pipelet[pipelet.root.name] = pipelet
    new_topk_pipelets = [root_name_to_pipelet[p.root.name] for p in topk_pipelets]

    pipe_prgs = ControlFlowGraph._get_topk_pipelet_groups(irgraph_pipe, cfg, new_topk_pipelets)
    root_name_to_group: Dict[TableName, PipeletGroup] = {}
    for pp in pipe_prgs:
        root_name_to_group[pp.root.name] = pp

    for op in options:
        assert isinstance(op, PipeletGroupOption), f"The option is not PipeletGroupOption. Got type{op}"
        pipelet_options = op.pipelet_options
        grp_options = op.group_options

        # Only has pipelet options, we can sum up the pipelet option costs and gains
        if grp_options is None:
            assert pipelet_options is not None, f"pipelet_options is None when the group_options is also None."
            apply_pipelet_options(pipelet_options, irgraph_pipe)
            continue

        assert len(grp_options) == 1, (
            f"The group option should have a GroupMergeOption, " f"but got {type(grp_options[0])}"
        )

        if isinstance(grp_options[0], GroupMergeOption):
            JsonPlanner.apply_group_merge(root_name_to_group[grp_options[0].root.name])
        elif isinstance(grp_options[0], GroupCacheOption):
            # apply on the copied pipelet groups
            JsonPlanner.apply_group_cache(root_name_to_group[grp_options[0].root.name])
        else:
            raise TypeError(f"Unrecognized group option type {type(grp_options[0])}")


def eval_program(program_option: ProgramOption, topk_pipelets=None) -> Optional[ProgramEvalMetric]:
    """Evaluate the whole program gain and cost as a whole"""
    if program_option.option is None:
        return

    for i in range(1, len(program_option.option)):
        assert type(program_option.option[0]) == type(
            program_option.option[i]
        ), f"List[AggregatedOption] has different instance types"

    irgraph_pipe_copy1 = deepcopy(program_option.irgraph_pipe)
    irgraph_pipe_copy2 = deepcopy(program_option.irgraph_pipe)
    # re-split the original pipelet before we evaluate it
    JsonManager.from_plan_labeling_to_single_json(irgraph_pipe_copy1.target, irgraph_pipe_copy1.ir_graph)
    org_eval_metric = irgraph_pipe_copy1.eval()
    if isinstance(program_option.option[0], PipeletOption):
        apply_pipelet_options(program_option.option, irgraph_pipe_copy2)
    elif isinstance(program_option.option[0], PipeletGroupOption):
        assert config.GROUP_CACHE_ENABLED
        assert topk_pipelets != None, f"Need topk information to evaluate group options"
        apply_pipelet_group_options(program_option.option, irgraph_pipe_copy2, topk_pipelets)
    else:
        raise Exception(f"Unsupported option instance type {type(op)}")
    JsonManager.from_plan_labeling_to_single_json(irgraph_pipe_copy2.target, irgraph_pipe_copy2.ir_graph)
    opt_eval_metric = irgraph_pipe_copy2.eval()

    return ProgramEvalMetric(
        org_p50_lat=org_eval_metric._median_latency,
        opt_p50_lat=opt_eval_metric._median_latency,
        org_p99_lat=org_eval_metric._p99_latency,
        opt_p99_lat=opt_eval_metric._p99_latency,
        org_avg_lat=org_eval_metric._average_latency,
        opt_avg_lat=opt_eval_metric._average_latency,
        org_inter_pkt_gap=org_eval_metric._inter_packet_gap,
        opt_inter_pkt_gap=opt_eval_metric._inter_packet_gap,
    )


def main():
    set_log_level(LogLevel.ERROR)  # close DEBUG info
    enabled_methods = [OptimizeMethod.REORDER, OptimizeMethod.MERGE, OptimizeMethod.CACHE]

    for i in range(10):
        json_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "input_data", f"prog_{i}.p4.json")
        runtime_stats_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "input_data", f"prog_{i}_10th.pkl"
        )

        with open(runtime_stats_path, "rb") as f:
            runtime_stats = pickle.load(f)

        print(f"program: {json_path}")

        prog_opt, time1 = topk_gain_and_time_with_runtime_stats(json_path, 0.3, enabled_methods, runtime_stats)

        if prog_opt != None:
            gain1 = 1.0 / prog_opt.opt_avg_lat / (1.0 / prog_opt.org_avg_lat)
        else:
            gain1 = 1

        print(f"Top-30% optimization, gain: {round(gain1, 2)}x, time: {time1}s")

        prog_opt2, time2 = topk_gain_and_time_with_runtime_stats(json_path, 1, enabled_methods, runtime_stats)

        if prog_opt2 != None:
            gain2 = 1.0 / prog_opt2.opt_avg_lat / (1.0 / prog_opt2.org_avg_lat)
        else:
            gain2 = 1

        print(f"Full optimization, gain: {round(gain2, 2)}x, time: {time2}s")
        print("=" * 30)


if __name__ == "__main__":
    main()
