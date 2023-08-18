from typing import Tuple
import networkx as nx
import pytest
import os, sys, random
import mock_import
from runtime_CLI import RuntimeAPI
from unittest.mock import patch

from commons.constants import TOTAL_ENTRY_INSERTION, TOTAL_MEMORY, DeviceTargetType, OptimizeMethod, OptimizeTarget
from ir.match_key import MatchType
from commons.types import LatencyPdf, TargetLoadPdf
from targets.smart_nic import SmartNic
from targets.driver_api_implementation import get_valid_action_prim_num
from graph_optimizer.graph_optimizer import Optimizer
from graph_optimizer.json_manager import JsonManager
from graph_optimizer.runtime_states import RuntimeStates
from graph_optimizer.options import PipeletOption, SoftmoveOption

import utils


class TestEval:
    def test_eval(self):
        pipelet = utils.create_pipelet(6, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 0, 0, 1, 0, 1])
        utils.set_table_current_sizes(tables, [1, 1, 1, 1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1, 1, 1, 1])
        pipelet.irgraph_pipe.target = SmartNic()
        pipelet.irgraph_pipe.eval()

    @pytest.mark.parametrize(
        "json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "cost_model1", "test.p4.json")],
    )
    def test_get_latency_stats(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")

        lat_median, lat_p99, lat_average = ingress_graph._get_latency_stats([(100, 0.5), (200, 0.25), (400, 0.25)])
        assert lat_median == 100
        assert 400 > lat_p99 > 390
        assert lat_average == 200


@patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
class TestPipeletOptionEval:
    @pytest.mark.parametrize(
        "json_path", [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "reorder", "test.p4.json")]
    )
    def test_reorder_zero_cost(self, retrieve_runtime_states, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        conds = list(ingress_graph.conditions)
        tns = [t.name for t in tables]
        retrieve_runtime_states.return_value = RuntimeStates(
            table_to_counts={
                tns[0]: utils._gen_count_profile_reorder(tables[0], 1, 10),
                tns[1]: utils._gen_count_profile_reorder(tables[1], 2, 10),
                tns[2]: utils._gen_count_profile_reorder(tables[2], 5, 10),
            },
            cond_to_counts={},
            table_to_size={tns[0]: 1, tns[1]: 1, tns[2]: 1},
            table_to_entry_insertion_count={tns[0]: 1, tns[1]: 1, tns[2]: 1},
            total_memory=TOTAL_MEMORY,
            total_entry_insertion_bandwidth=TOTAL_ENTRY_INSERTION,
            mapping_dict={"tables": {t.name: {"entries": utils._gen_entries_json()} for t in tables}},
        )
        pipelet_options = utils._call_optimizer(irg, [OptimizeMethod.REORDER], OptimizeTarget.LATENCY)
        assert pipelet_options != None
        assert len(pipelet_options.option) == 1
        assert pipelet_options.option[0].mcost == 0
        assert pipelet_options.option[0].icost == 0

    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "synthesized", "prog_0.p4.json"),
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "simple_dash", "test.p4.json"),
        ],
    )
    def test_optimization_nonzero_cost(self, retrieve_runtime_states, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        conds = list(ingress_graph.conditions)
        tns = [t.name for t in tables]
        cns = [c.name for c in conds]
        retrieve_runtime_states.return_value = RuntimeStates(
            table_to_counts={tns[i]: utils._gen_count_profile_even(tables[i]) for i in range(len(tables))},
            cond_to_counts={cns[i]: utils._gen_count_profile_even(conds[i]) for i in range(len(conds))},
            table_to_size={tns[i]: 1 for i in range(len(tables))},
            table_to_entry_insertion_count={tns[i]: 1 for i in range(len(tables))},
            total_memory=TOTAL_MEMORY,
            total_entry_insertion_bandwidth=TOTAL_ENTRY_INSERTION,
            mapping_dict={"tables": {t.name: {"entries": utils._gen_entries_json()} for t in tables}},
        )
        prog_option = utils._call_optimizer(
            irg, [OptimizeMethod.SOFTCOPY, OptimizeMethod.SOFTMOVE, OptimizeMethod.MERGE], OptimizeTarget.LATENCY
        )
        assert prog_option != None
        for pipe_opt in prog_option.option:
            assert isinstance(pipe_opt, PipeletOption)
            if pipe_opt.combined_options is not None and not (
                len(pipe_opt.combined_options) == 1 and isinstance(pipe_opt.combined_options[0], SoftmoveOption)
            ):
                print(pipe_opt)
                assert pipe_opt.icost != 0 and pipe_opt.mcost != 0


@patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
class TestProgramOptionEval:
    hw_steer = DeviceTargetType.HW_STEERING
    sw_steer = DeviceTargetType.SW_STEERING

    def get_latency_pdf(
        self,
        retrieve_runtime_states,
        json_path,
        branch_counts={"true": 10, "false": 10},
    ) -> Tuple[LatencyPdf, TargetLoadPdf]:
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        conds = list(ingress_graph.conditions)

        retrieve_runtime_states.return_value = utils.gen_runtime_stats(
            tables=tables, conds=conds, even_counter_distr=True, branch_counts=branch_counts
        )
        json_manager = JsonManager(api=RuntimeAPI())
        runtime_states = json_manager.retrieve_runtime_states(f"{round}_presplit_preopt.json")
        optimizer = Optimizer(api=RuntimeAPI(), sampling_period_us=1000000)
        optimizer._update_pipeline_stats(irg, runtime_states)

        JsonManager.from_plan_labeling_to_single_json(ingress_graph.target, ingress_graph.ir_graph)
        root_table = next(nx.topological_sort(ingress_graph))
        for n in ingress_graph.nodes:
            n.latency_eval = None
        latency_pdf, per_target_load = ingress_graph._recursive_latency_eval(root_table)
        return latency_pdf, per_target_load

    @pytest.mark.parametrize(
        "json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "cost_model1", "test.p4.json")],
    )
    def test_latencypdf_cost_model1(self, retrieve_runtime_states, json_path):
        latency_pdf, target_load = self.get_latency_pdf(retrieve_runtime_states, json_path)
        assert sorted(latency_pdf) == sorted([(800, 1)])
        assert sorted(target_load[self.hw_steer]) == sorted([(800, 1)])
        assert sorted(target_load[self.sw_steer]) == sorted([(0, 1)])


class TestActionPrimitiveLength:
    @pytest.mark.parametrize(
        "json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "action_prim_len", "test.p4.json")],
    )
    def test_primitive_length(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        irg.action_id_to_action

        no_path_trace1 = irg.action_id_to_action[0]
        no_path_trace2 = irg.action_id_to_action[1]
        path_trace_len6 = irg.action_id_to_action[2]
        path_trace_len2 = irg.action_id_to_action[3]
        path_trace_error1 = irg.action_id_to_action[4]
        path_trace_error2 = irg.action_id_to_action[5]
        assert no_path_trace1.name == "MyIngress.tab1_act1"
        assert no_path_trace2.name == "MyIngress.tab1_act2"
        assert path_trace_len6.name == "sirius_ingress.route_vnet"
        assert path_trace_len2.name == "NoAction"
        assert path_trace_error1.name == "sirius_ingress.route_vnet_error"
        assert path_trace_error2.name == "NoAction_error"

        assert get_valid_action_prim_num(no_path_trace1.primitives) == 3
        assert get_valid_action_prim_num(no_path_trace2.primitives) == 3
        assert get_valid_action_prim_num(path_trace_len6.primitives) == 2
        assert get_valid_action_prim_num(path_trace_len2.primitives) == 0
        assert get_valid_action_prim_num(path_trace_error1.primitives) == 0
        assert get_valid_action_prim_num(path_trace_error2.primitives) == 0
