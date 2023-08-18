import os
import pytest
import mock_import
from runtime_CLI import RuntimeAPI
from unittest.mock import patch
from typing import Dict, List, Tuple

from commons.types import TableName
from graph_optimizer.json_manager import JsonDeployer, JsonManager, JsonPlanner
from graph_optimizer.pipelet import Pipelet
from graph_optimizer.graph_optimizer import Optimizer
import utils


class TestPipelet:
    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "pipelet_pipelet_group", "test.p4.json"
            )
        ],
    )
    def test_pipelet_partition(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        pipelet_start_length: List[Tuple[TableName, int]] = []
        for p in pipelets:
            pipelet_start_length.append((p.root.name, p.length))

        assert len(pipelets) == 17
        assert ("MyIngress.tab01", 1) in pipelet_start_length
        assert ("MyIngress.tab02", 2) in pipelet_start_length
        assert ("MyIngress.tab04", 2) in pipelet_start_length
        assert ("MyIngress.tab06", 1) in pipelet_start_length
        assert ("MyIngress.tab07", 1) in pipelet_start_length
        assert ("MyIngress.tab18", 2) in pipelet_start_length
        assert ("MyIngress.tab20", 1) in pipelet_start_length
        assert ("MyIngress.tab08", 1) in pipelet_start_length
        assert ("MyIngress.tab09", 2) in pipelet_start_length
        assert ("MyIngress.tab_switch", 1) in pipelet_start_length
        assert ("MyIngress.tab11", 2) in pipelet_start_length
        assert ("MyIngress.tab13", 1) in pipelet_start_length
        assert ("MyIngress.tab14", 1) in pipelet_start_length
        assert ("MyIngress.tab15", 1) in pipelet_start_length
        assert ("MyIngress.tab16", 1) in pipelet_start_length
        assert ("MyIngress.tab17", 1) in pipelet_start_length
        assert ("MyIngress.tab21", 1) in pipelet_start_length

    def float_equal(self, a, b):
        return True if abs(a - b) < 0.00001 else False

    @pytest.mark.parametrize(
        "json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "pipelet_prob", "test.p4.json")],
    )
    @patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
    def test_pipelet_probability(self, retrieve_runtime_states, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")

        # setup probability
        tables = list(ingress_graph.tables)
        conds = list(ingress_graph.conditions)
        branch_counts = {"true": 30, "false": 10}

        retrieve_runtime_states.return_value = utils.gen_runtime_stats(
            tables=tables, conds=conds, even_counter_distr=False, branch_counts=branch_counts
        )
        json_manager = JsonManager(api=RuntimeAPI())
        runtime_states = json_manager.retrieve_runtime_states(f"{round}_presplit_preopt.json")
        optimizer = Optimizer(api=RuntimeAPI(), sampling_period_us=1000000)
        optimizer._update_pipeline_stats(irg, runtime_states)

        # test prob
        pipelets = JsonPlanner.get_pipelets(ingress_graph)
        name_to_pipelet: Dict[TableName, Pipelet] = {}
        for p in pipelets:
            name_to_pipelet[p.root.name] = p

        assert self.float_equal(name_to_pipelet["MyIngress.tab01"].prob_to_it(), 1.0)
        assert self.float_equal(name_to_pipelet["MyIngress.tab02"].prob_to_it(), 0.75)
        assert self.float_equal(name_to_pipelet["MyIngress.tab06"].prob_to_it(), 0.75 * 0.25 * 0.75 * 0.75)
        assert self.float_equal(name_to_pipelet["MyIngress.tab20"].prob_to_it(), 0.75 * 0.25 * 0.25)
        assert self.float_equal(name_to_pipelet["MyIngress.tab09"].prob_to_it(), 0.75 * 0.25 + 0.25)
        tab09_prob = 0.75 * 0.25 + 0.25
        assert self.float_equal(name_to_pipelet["MyIngress.tab_switch"].prob_to_it(), tab09_prob * 0.25)
        tab_switch_prob = tab09_prob * 0.25
        assert self.float_equal(name_to_pipelet["MyIngress.tab11"].prob_to_it(), tab_switch_prob * 1 / 4)
        after_switch_prob = tab_switch_prob - tab_switch_prob * 1 / 4 * 0.75
        assert self.float_equal(name_to_pipelet["MyIngress.tab14"].prob_to_it(), after_switch_prob * 0.75)
        assert self.float_equal(name_to_pipelet["MyIngress.tab15"].prob_to_it(), after_switch_prob * 0.25 * 0.75)
        assert self.float_equal(name_to_pipelet["MyIngress.tab16"].prob_to_it(), after_switch_prob * 0.25 * 0.25 * 0.75)

    @pytest.mark.parametrize(
        "json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "pipelet_prob", "test.p4.json")],
    )
    @patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
    def test_pipelet_eval(self, retrieve_runtime_states, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")

        # setup probability
        tables = list(ingress_graph.tables)
        conds = list(ingress_graph.conditions)
        branch_counts = {"true": 30, "false": 10}

        retrieve_runtime_states.return_value = utils.gen_runtime_stats(
            tables=tables, conds=conds, even_counter_distr=False, branch_counts=branch_counts
        )
        json_manager = JsonManager(api=RuntimeAPI())
        runtime_states = json_manager.retrieve_runtime_states(f"{round}_presplit_preopt.json")
        optimizer = Optimizer(api=RuntimeAPI(), sampling_period_us=1000000)
        optimizer._update_pipeline_stats(irg, runtime_states)

        JsonDeployer.from_optimized_type_to_target_type(irg)

        # test prob
        pipelets = JsonPlanner.get_pipelets(ingress_graph)
        name_to_pipelet: Dict[TableName, Pipelet] = {}
        for p in pipelets:
            name_to_pipelet[p.root.name] = p

        # TODO: need to recompute based on the NIC parameters
        # assert name_to_pipelet["MyIngress.tab01"].eval()._average_latency == 300
        # assert name_to_pipelet["MyIngress.tab02"].eval()._average_latency == int((300+300*0.25)*0.75)
        # assert name_to_pipelet["MyIngress.tab04"].eval()._average_latency == int(600*0.75*0.25*0.75)
        # assert name_to_pipelet["MyIngress.tab06"].eval()._average_latency == int(300*0.75*0.25*0.75*0.75)
        # assert name_to_pipelet["MyIngress.tab20"].eval()._average_latency == int(300*0.75*0.25*0.25)
        # assert name_to_pipelet["MyIngress.tab09"].eval()._average_latency == int((300+300*0.25)*(0.75*0.25 + 0.25))
        # tab09_prob = 0.75*0.25 + 0.25
        # assert name_to_pipelet["MyIngress.tab_switch"].eval()._average_latency == int(300*(tab09_prob*0.25))
        # tab_switch_prob = tab09_prob*0.25
        # after_switch_prob = tab_switch_prob - tab_switch_prob*1/4*0.75
        # assert name_to_pipelet["MyIngress.tab14"].eval()._average_latency == int(300*(after_switch_prob*0.75))
        # assert name_to_pipelet["MyIngress.tab16"].eval()._average_latency == int(300*(after_switch_prob*0.25*0.25*0.75))
