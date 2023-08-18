import os
import pytest
import mock_import
import copy
from runtime_CLI import RuntimeAPI
from unittest.mock import patch
from typing import Dict, List, Tuple

from commons.types import TableName
from commons.constants import CFGNodeType
from graph_optimizer.json_manager import JsonDeployer, JsonManager, JsonPlanner
from graph_optimizer.control_flow_graph import ControlFlowGraph
from graph_optimizer.pipelet import Pipelet, PipeletGroup
from graph_optimizer.graph_optimizer import Optimizer
from commons.constants import OptimizeTarget

import utils
import utils as TestUtils


class TestControlFlowGraph:
    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "pipelet_pipelet_group", "test.p4.json"
            )
        ],
    )
    def test_generating_complex_cfg(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)

    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "pipelet_pipelet_group", "test.p4.json"
            )
        ],
    )
    def test_draw_cfg(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")

    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "simple_test_no_const_action", "test.p4.json"
            )
        ],
    )
    def test_get_dominators(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        cfg_nodes = list(cfg.nodes)

        for cfg_node in cfg_nodes:
            print("Current target node:", cfg_node)
            dominators = []
            dominators = ControlFlowGraph._get_dominators(cfg, cfg_node, False, cfg.root)
            print("Dominators:", dominators)

    @pytest.mark.parametrize(
        "json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "test_cfg_and_pipelet", "test.p4.json")],
    )
    def test_get_aggregations(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        cfg_nodes = list(cfg.nodes)

        ControlFlowGraph._get_aggregation(cfg)

    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "pipelet_pipelet_group", "test.p4.json"
            )
        ],
    )
    def test_cfg_node_and_pipelet_content(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        cfg_nodes = list(cfg.nodes)
        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]

        for cfg_node in cfg_nodes:
            if cfg_node.node_type == CFGNodeType.TABLE:
                cfg_ir_nodes_list = cfg_node.ir_nodes
                first_ir_node = cfg_ir_nodes_list[0]
                assert first_ir_node in list(topk_pipelet_dict.keys())
                correponding_pipelet = topk_pipelet_dict[first_ir_node]
                pipelet_ir_node_list = correponding_pipelet.tables

                for ir_node in cfg_ir_nodes_list:
                    assert ir_node in pipelet_ir_node_list


@pytest.mark.parametrize(
    "json_path",
    [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "test_cfg_and_pipelet", "test.p4.json")],
)
class TestGetTopkPipeletGroup:
    def test_mini_topk_1(self, json_path):
        """several mini topk pipelets that can't be combined"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            # Root's successor
            if str(cfg_node) == "MyIngress.tab1":
                test_nodes.append(cfg_node)
            # Sink's predecessor
            if str(cfg_node) == "MyIngress.tab23":
                test_nodes.append(cfg_node)
            # normal pipelet in main branch
            if str(cfg_node) == "MyIngress.tab12":
                test_nodes.append(cfg_node)
            # normal pipelet in condition branch
            if str(cfg_node) == "MyIngress.tab7":
                test_nodes.append(cfg_node)
            # normal pipelet in sub condition branch
            if str(cfg_node) == "MyIngress.tab20":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 5

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 5

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 5
        assert topk_pipelet_groups[0].root.name == "MyIngress.tab1"
        assert topk_pipelet_groups[0].sink.name == "node_6"
        assert topk_pipelet_groups[1].root.name == "MyIngress.tab7"
        assert topk_pipelet_groups[1].sink.name == "MyIngress.tab12"
        assert topk_pipelet_groups[2].root.name == "MyIngress.tab12"
        assert topk_pipelet_groups[2].sink.name == "node_16"
        assert topk_pipelet_groups[3].root.name == "MyIngress.tab20"
        assert topk_pipelet_groups[3].sink.name == "MyIngress.tab22"
        assert topk_pipelet_groups[4].root.name == "MyIngress.tab23"
        assert topk_pipelet_groups[4].sink.name == "Sink"

    def test_mini_topk_2(self, json_path):
        """two mini topk pipelets that can't be combined"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            # a topk pipelet in a condition branch
            if str(cfg_node) == "MyIngress.tab5":
                test_nodes.append(cfg_node)
            # a topk pipelet in a sub condition branch
            if str(cfg_node) == "MyIngress.tab9":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 2

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 2

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 2
        assert topk_pipelet_groups[0].root.name == "node_6"
        assert topk_pipelet_groups[0].sink.name == "MyIngress.tab_switch1"
        assert topk_pipelet_groups[1].root.name == "MyIngress.tab9"
        assert topk_pipelet_groups[1].sink.name == "MyIngress.tab11"

    def test_mini_topk_3(self, json_path):
        """two mini topk pipelets that can't be combined"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            # a topk pipelet in a condition branch
            if str(cfg_node) == "MyIngress.tab8":
                test_nodes.append(cfg_node)
            # an aggregation topk pipelet in the same condition branch
            if str(cfg_node) == "MyIngress.tab11":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 2

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 2

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 2
        assert topk_pipelet_groups[0].root.name == "MyIngress.tab8"
        assert topk_pipelet_groups[0].sink.name == "MyIngress.tab11"
        assert topk_pipelet_groups[1].root.name == "MyIngress.tab11"
        assert topk_pipelet_groups[1].sink.name == "MyIngress.tab12"

    def test_groups_1(self, json_path):
        """All topk pipelets of a sub condition branch that can be combined"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            # a ture case topk pipelet in a condition branch
            if str(cfg_node) == "MyIngress.tab8":
                test_nodes.append(cfg_node)
            # a false case topk pipelet in the same condition branch
            if str(cfg_node) == "MyIngress.tab9":
                test_nodes.append(cfg_node)
            # the aggregation topk pipelet in the same condition branch
            if str(cfg_node) == "MyIngress.tab11":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 3

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 3

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 1
        assert topk_pipelet_groups[0].root.name == "node_10"
        assert topk_pipelet_groups[0].sink.name == "MyIngress.tab12"

    def test_groups_2(self, json_path):
        """All topk pipelets of a condition branch that can be combined,
        and this condition branch also includes a sub condition branch"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            # a switch topk pipelet in the condition branch
            # temporarily cannot support switch table topk
            # if str(cfg_node) == "MyIngress.tab_switch1":
            #     test_nodes.append(cfg_node)
            # a swich case topk pipelet in the condition branch
            if str(cfg_node) == "MyIngress.tab7":
                test_nodes.append(cfg_node)
            # the aggregation topk pipelet in the condition branch
            if str(cfg_node) == "MyIngress.tab12":
                test_nodes.append(cfg_node)
            # a ture case topk pipelet in the sub condition branch
            if str(cfg_node) == "MyIngress.tab8":
                test_nodes.append(cfg_node)
            # a false case topk pipelet in the sub condition branch
            if str(cfg_node) == "MyIngress.tab9":
                test_nodes.append(cfg_node)
            # the aggregation topk pipelet in the sub condition branch
            if str(cfg_node) == "MyIngress.tab11":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 5

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 5

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 1
        assert topk_pipelet_groups[0].root.name == "MyIngress.tab_switch1"
        assert topk_pipelet_groups[0].sink.name == "node_16"

    def test_groups_3(self, json_path):
        """A set of topk pipelets of a condition branch that can be combined,
        the set lack the aggregation pipelet, so it will result in a smaller group"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            # a ture case topk pipelet in the condition branch
            if str(cfg_node) == "MyIngress.tab8":
                test_nodes.append(cfg_node)
            # a false case topk pipelet in the same condition branch
            if str(cfg_node) == "MyIngress.tab9":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 2

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 2

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 1
        assert topk_pipelet_groups[0].root.name == "node_10"
        assert topk_pipelet_groups[0].sink.name == "MyIngress.tab11"

    def test_groups_4(self, json_path):
        """All topk pipelets of a condition branch that can be combined,
        and the topk pipelet of the predecessor of the condition branch,
        so they can generate a larger group"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            # a ture case topk pipelet in the condition branch
            if str(cfg_node) == "MyIngress.tab15":
                test_nodes.append(cfg_node)
            # a aggregation topk pipelet in the same condition branch
            if str(cfg_node) == "MyIngress.tab17":
                test_nodes.append(cfg_node)
            # the predecessor topk pipelet of the condition branch
            if str(cfg_node) == "MyIngress.tab13":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 3

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 3

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 1
        assert topk_pipelet_groups[0].root.name == "MyIngress.tab13"
        assert topk_pipelet_groups[0].sink.name == "MyIngress.tab23"

    def test_groups_5(self, json_path):
        """multiple pipelet groups"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            # topk pipelet in group1 (larger condition group)
            if str(cfg_node) == "MyIngress.tab1":
                test_nodes.append(cfg_node)
            # topk pipelet in group1
            if str(cfg_node) == "MyIngress.tab5":
                test_nodes.append(cfg_node)

            # topk pipelet in group2 (only inludes one mini topk piplet)
            if str(cfg_node) == "MyIngress.tab7":
                test_nodes.append(cfg_node)

            # topk pipelet in group3 (smaller sub condition group)
            if str(cfg_node) == "MyIngress.tab8":
                test_nodes.append(cfg_node)
            # topk pipelet in group3
            if str(cfg_node) == "MyIngress.tab9":
                test_nodes.append(cfg_node)

            # topk pipelet in group4 (a condition group includes sub condition groups)
            if str(cfg_node) == "MyIngress.tab13":
                test_nodes.append(cfg_node)
            # topk pipelet in group4
            if str(cfg_node) == "MyIngress.tab14":
                test_nodes.append(cfg_node)
            # topk pipelet in group4
            if str(cfg_node) == "MyIngress.tab15":
                test_nodes.append(cfg_node)
            # topk pipelet in group4
            if str(cfg_node) == "MyIngress.tab17":
                test_nodes.append(cfg_node)
            # topk pipelet in group4
            # if str(cfg_node) == "MyIngress.tab_switch2":
            #     test_nodes.append(cfg_node)
            # topk pipelet in group4
            if str(cfg_node) == "MyIngress.tab19":
                test_nodes.append(cfg_node)
            # topk pipelet in group4
            if str(cfg_node) == "MyIngress.tab20":
                test_nodes.append(cfg_node)
            # topk pipelet in group4
            if str(cfg_node) == "MyIngress.tab21":
                test_nodes.append(cfg_node)
            # topk pipelet in group4
            if str(cfg_node) == "MyIngress.tab22":
                test_nodes.append(cfg_node)
            # topk pipelet in group4
            if str(cfg_node) == "MyIngress.tab23":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 14

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 14

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 4
        assert topk_pipelet_groups[0].root.name == "MyIngress.tab1"
        assert topk_pipelet_groups[0].sink.name == "MyIngress.tab_switch1"
        assert topk_pipelet_groups[1].root.name == "MyIngress.tab7"
        assert topk_pipelet_groups[1].sink.name == "MyIngress.tab12"
        assert topk_pipelet_groups[2].root.name == "node_10"
        assert topk_pipelet_groups[2].sink.name == "MyIngress.tab11"
        assert topk_pipelet_groups[3].root.name == "node_16"
        assert topk_pipelet_groups[3].sink.name == "Sink"

    def test_groups_6(self, json_path):
        """Two consecutive condition branches"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            # topk pipelet in group1 (larger condition group)
            if str(cfg_node) == "MyIngress.tab1":
                test_nodes.append(cfg_node)
            # topk pipelet in group1
            if str(cfg_node) == "MyIngress.tab5":
                test_nodes.append(cfg_node)

            # topk pipelet in group2
            # if str(cfg_node) == "MyIngress.tab_switch1":
            #     test_nodes.append(cfg_node)
            # topk pipelet in group2
            if str(cfg_node) == "MyIngress.tab7":
                test_nodes.append(cfg_node)
            # topk pipelet in group2
            if str(cfg_node) == "MyIngress.tab8":
                test_nodes.append(cfg_node)
            # topk pipelet in group2
            if str(cfg_node) == "MyIngress.tab9":
                test_nodes.append(cfg_node)
            # topk pipelet in group2
            if str(cfg_node) == "MyIngress.tab11":
                test_nodes.append(cfg_node)
            # topk pipelet in group2
            if str(cfg_node) == "MyIngress.tab12":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 7

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 7

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 2
        assert topk_pipelet_groups[0].root.name == "MyIngress.tab1"
        assert topk_pipelet_groups[0].sink.name == "MyIngress.tab_switch1"
        assert topk_pipelet_groups[1].root.name == "MyIngress.tab_switch1"
        assert topk_pipelet_groups[1].sink.name == "node_16"

    def test_groups_7(self, json_path):
        """test smaller condition group,
        and this condition branch includes sub condition branch
        """
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            # if str(cfg_node) == "MyIngress.tab_switch1":
            #     test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab7":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab8":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab9":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab11":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 4

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 4

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 1
        assert topk_pipelet_groups[0].root.name == "MyIngress.tab_switch1"
        assert topk_pipelet_groups[0].sink.name == "MyIngress.tab12"


@pytest.mark.parametrize(
    "json_path",
    [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "pipelet_pipelet_group", "test.p4.json")],
)
class TestSpecialTopkPipeletGroup1:
    def test_1(self, json_path):
        """two independent pipelets"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab07":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab18":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab19":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 2

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 2

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 2
        assert topk_pipelet_groups[0].root.name == "MyIngress.tab07"
        assert topk_pipelet_groups[0].sink.name == "node_12"
        assert topk_pipelet_groups[1].root.name == "MyIngress.tab18"
        assert topk_pipelet_groups[1].sink.name == "MyIngress.tab20"

    def test_shared_aggregation1(self, json_path):
        """whole condition branch including the sub branch that shares the aggregation
        can be one big group"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab04":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab07":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab06":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab08":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab18":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab20":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 6

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 6

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 1
        assert topk_pipelet_groups[0].root.name == "node_6"
        assert topk_pipelet_groups[0].sink.name == "MyIngress.tab09"

    def test_shared_aggregation2(self, json_path):
        """whole condition branch including multiple sub branch that shares the aggregation
        can be one big group"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab14":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab15":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab16":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab17":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 4

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 4

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 1
        assert topk_pipelet_groups[0].root.name == "node_24"
        assert topk_pipelet_groups[0].sink.name == "Sink"

    def test_shared_aggregation3(self, json_path):
        """a sub condition branch including another sub branch that shares the aggregation
        can be one small group"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab15":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab16":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab17":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 3

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 3

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 1
        assert topk_pipelet_groups[0].root.name == "node_26"
        assert topk_pipelet_groups[0].sink.name == "Sink"

    def test_shared_aggregation4(self, json_path):
        """a sub condition branch shares the aggregation cannot form one big group"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab04":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab06":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab08":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 3

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 3

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 3
        assert topk_pipelet_groups[0].root.name == "MyIngress.tab04"
        assert topk_pipelet_groups[0].sink.name == "node_9"
        assert topk_pipelet_groups[1].root.name == "MyIngress.tab06"
        assert topk_pipelet_groups[1].sink.name == "MyIngress.tab08"
        assert topk_pipelet_groups[2].root.name == "MyIngress.tab08"
        assert topk_pipelet_groups[2].sink.name == "MyIngress.tab09"

    def test_shared_aggregation5(self, json_path):
        """a sub condition branch shares the aggregation cannot form one big group"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab04":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab06":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab08":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab18":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab20":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 5

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 5

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 4
        assert topk_pipelet_groups[0].root.name == "MyIngress.tab04"
        assert topk_pipelet_groups[0].sink.name == "node_9"
        assert topk_pipelet_groups[1].root.name == "MyIngress.tab06"
        assert topk_pipelet_groups[1].sink.name == "MyIngress.tab08"
        assert topk_pipelet_groups[2].root.name == "node_12"
        assert topk_pipelet_groups[2].sink.name == "MyIngress.tab08"
        assert topk_pipelet_groups[3].root.name == "MyIngress.tab08"
        assert topk_pipelet_groups[3].sink.name == "MyIngress.tab09"

    def test_shared_aggregation6(self, json_path):
        """a sub condition branch shares the aggregation cannot form one big group"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab02":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab04":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab06":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab07":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab08":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab09":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab18":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab20":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 8

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 8

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 1
        assert topk_pipelet_groups[0].root.name == "node_3"
        assert topk_pipelet_groups[0].sink.name == "MyIngress.tab_switch"


@pytest.mark.parametrize(
    "json_path",
    [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "test_cfg_and_pipelet2", "test.p4.json")],
)
class TestSpecialTopkPipeletGroup2:
    def test_shared_aggregation1(self, json_path):
        """whole sub condition branch including other sub branchs that shares the aggregation
        cannot be one big group"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab1":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab2":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab3":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab4":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab5":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 5

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 5

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 2
        assert topk_pipelet_groups[0].root.name == "MyIngress.tab1"
        assert topk_pipelet_groups[0].sink.name == "node_4"
        assert topk_pipelet_groups[1].root.name == "MyIngress.tab2"
        assert topk_pipelet_groups[1].sink.name == "MyIngress.tab13"

    def test_shared_aggregation2(self, json_path):
        """whole sub condition branch including other sub branchs that shares the aggregation
        can be one big group without the aggregation node"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab1":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab2":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab3":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab4":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab5":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab6":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab7":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 7

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 7

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 1
        assert topk_pipelet_groups[0].root.name == "MyIngress.tab1"
        assert topk_pipelet_groups[0].sink.name == "MyIngress.tab13"

    def test_shared_aggregation3(self, json_path):
        """whole sub condition branch including other sub branchs that shares the aggregation
        cannot be one big group with the aggregation node"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab1":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab2":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab3":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab4":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab5":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab6":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab7":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab13":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 8

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 8

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 2
        assert topk_pipelet_groups[0].root.name == "MyIngress.tab1"
        assert topk_pipelet_groups[0].sink.name == "MyIngress.tab13"
        assert topk_pipelet_groups[1].root.name == "MyIngress.tab13"
        assert topk_pipelet_groups[1].sink.name == "Sink"

    def test_shared_aggregation4(self, json_path):
        """whole sub condition branch including other sub branchs that shares the aggregation
        can be one big group with the aggregation node"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab1":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab2":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab3":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab4":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab5":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab6":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab7":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab9":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab10":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab11":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab12":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab13":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 12

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 12

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 1
        assert topk_pipelet_groups[0].root.name == "node_2"
        assert topk_pipelet_groups[0].sink.name == "Sink"

    def test_shared_aggregation5(self, json_path):
        """whole condition branch including other sub branchs that shares the aggregation
        cannot be one big group with the aggregation node"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab9":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab10":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab11":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab12":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab13":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 5

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 5

        # test get topk pipelet groups
        topk_pipelet_groups = []
        topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        assert len(topk_pipelet_groups) == 4
        assert topk_pipelet_groups[0].root.name == "MyIngress.tab9"
        assert topk_pipelet_groups[0].sink.name == "MyIngress.tab13"
        assert topk_pipelet_groups[1].root.name == "node_16"
        assert topk_pipelet_groups[1].sink.name == "node_19"
        assert topk_pipelet_groups[2].root.name == "MyIngress.tab12"
        assert topk_pipelet_groups[2].sink.name == "MyIngress.tab13"
        assert topk_pipelet_groups[3].root.name == "MyIngress.tab13"
        assert topk_pipelet_groups[3].sink.name == "Sink"


@pytest.mark.parametrize(
    "json_path",
    [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "test_cfg_and_pipelet3", "test.p4.json")],
)
class TestTopkPipeletGroupSwitchCase:
    """test some cases of switch branch"""

    def test1(self, json_path):
        """one switch table and a normal table"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab1":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab_switch1":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 2

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 2

        # test get topk pipelet groups
        # TODO: unsupported for swith-case table as topk
        # topk_pipelet_groups = []
        # topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        # assert len(topk_pipelet_groups) == 2

    def test2(self, json_path):
        """switch branch and sub switch branch shares the aggregation
        cannot form one big group
        """
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab1":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab_switch1":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab_switch2":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab3":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab4":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab5":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 6

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 6

        # test get topk pipelet groups
        # TODO: unsupported for swith-case table as topk
        # topk_pipelet_groups = []
        # topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        # assert len(topk_pipelet_groups) == 6

    def test3(self, json_path):
        """switch branch and sub switch branch shares the aggregation
        can form one big group
        """
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab1":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab2":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab_switch1":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab_switch2":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab3":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab4":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab5":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 7

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 7

        # test get topk pipelet groups
        # TODO: unsupported for swith-case table as topk
        # topk_pipelet_groups = []
        # topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        # assert len(topk_pipelet_groups) == 1

    def test4(self, json_path):
        """switch branch lacking aggregation topk, can't form one group"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab_switch4":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab6":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab7":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 3

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 3

        # test get topk pipelet groups
        # TODO: unsupported for swith-case table as topk
        # topk_pipelet_groups = []
        # topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        # assert len(topk_pipelet_groups) == 3

    def test5(self, json_path):
        """switch branch lacking aggregation topk, can form one smaller group"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab_switch5":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab9":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab10":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 3

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 3

        # test get topk pipelet groups
        # TODO: unsupported for swith-case table as topk
        # topk_pipelet_groups = []
        # topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        # assert len(topk_pipelet_groups) == 1

    def test6(self, json_path):
        """switch branch with own aggregation topk, can form one group"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab_switch4":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab6":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab7":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab8":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 4

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 4

        # test get topk pipelet groups
        # TODO: unsupported for swith-case table as topk
        # topk_pipelet_groups = []
        # topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        # assert len(topk_pipelet_groups) == 1

    def test7(self, json_path):
        """switch branch without aggregation topk"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab_switch3":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab_switch4":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab6":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab7":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab8":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab_switch5":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab9":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab10":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 8

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 8

        # test get topk pipelet groups
        # TODO: unsupported for swith-case table as topk
        # topk_pipelet_groups = []
        # topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        # assert len(topk_pipelet_groups) == 3

    def test8(self, json_path):
        """switch branch without aggregation topk"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab_switch3":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab_switch4":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab6":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab7":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab8":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab_switch5":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab9":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab10":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab_switch6":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab11":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab12":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 11

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 11

        # test get topk pipelet groups
        # TODO: unsupported for swith-case table as topk
        # topk_pipelet_groups = []
        # topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        # assert len(topk_pipelet_groups) == 4

    def test9(self, json_path):
        """switch branch without aggregation topk"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab_switch6":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab11":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab12":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 3

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 3

        # test get topk pipelet groups
        # TODO: unsupported for swith-case table as topk
        # topk_pipelet_groups = []
        # topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        # assert len(topk_pipelet_groups) == 1

    def test10(self, json_path):
        """switch branch with shared aggregation topk"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab_switch6":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab11":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab12":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab13":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 4

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 4

        # test get topk pipelet groups
        # TODO: unsupported for swith-case table as topk
        # topk_pipelet_groups = []
        # topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        # assert len(topk_pipelet_groups) == 2

    def test11(self, json_path):
        """switch branch with shared aggregation topk"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
        ControlFlowGraph._get_aggregation(cfg)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # select the topk for testing
        cfg_nodes = list(cfg.nodes)
        test_nodes = []
        for cfg_node in cfg_nodes:
            if str(cfg_node) == "MyIngress.tab_switch3":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab_switch4":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab6":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab7":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab8":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab_switch5":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab9":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab10":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab_switch6":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab11":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab12":
                test_nodes.append(cfg_node)
            if str(cfg_node) == "MyIngress.tab13":
                test_nodes.append(cfg_node)

        assert len(test_nodes) == 12

        res = ControlFlowGraph._get_topk_pipelet_roots(pipelets)
        topk_pipelet_dict = res[1]
        topk_pipelet = []
        for test_node in test_nodes:
            topk_pipelet.append(topk_pipelet_dict[test_node.ir_nodes[0]])

        assert len(topk_pipelet) == 12

        # test get topk pipelet groups
        # TODO: unsupported for swith-case table as topk
        # topk_pipelet_groups = []
        # topk_pipelet_groups = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelet)

        # assert len(topk_pipelet_groups) == 1

    # def test_deep_copy(self, json_path):
    #     irg, target = JsonManager.retrieve_presplit(json_path)
    #     JsonManager.compile_time_json_planning(irg)
    #     ingress_graph = irg.get_pipe("ingress")
    #     cfg = ControlFlowGraph._build_cfg(ingress_graph)

    #     copied_cfg = copy.deepcopy(cfg)

    #     # cfg.remove_node(cfg.root)
    #     # assert cfg.root in cfg
    #     copied_nodes = list(copied_cfg.nodes)
    #     print("copied_nodes:", copied_nodes)
    #     assert copied_cfg.root in copied_cfg
    #     assert len(copied_nodes) > 0
    #     # assert (copied_cfg.root in cfg) or (copied_cfg.root in copied_cfg)
    #     # copied_cfg.remove_node(copied_cfg.root)
    #     # copied_nodes = list(copied_cfg.nodes)
    #     # nodes = list(cfg.nodes)
    #     # assert len(nodes) == 4
    #     # assert len(nodes) != len(copied_nodes)

    #     # ControlFlowGraph._draw_cfg(cfg, "cfg.pdf")
    #     # ControlFlowGraph._draw_cfg(copied_cfg, "copied_cfg.pdf")

    # def test_reserve_cfg(self, json_path):
    #     irg, target = JsonManager.retrieve_presplit(json_path)
    #     JsonManager.compile_time_json_planning(irg)
    #     ingress_graph = irg.get_pipe("ingress")
    #     cfg = ControlFlowGraph._build_cfg(ingress_graph)
    #     cfg_root = cfg.root
    #     cfg_sink = cfg.sink
    #     # print(list(cfg.edges))
    #     re_cfg = cfg._get_reserve_cfg_graph()
    #     print(list(re_cfg.edges))
    #     assert cfg_root in re_cfg
    #     assert cfg_sink in re_cfg
    #     # re_root = re_cfg.root
    #     # re_sink = re_cfg.sink

    # def test_get_topk_pipelet_group(self, json_path):
    #     irg, target = JsonManager.retrieve_presplit(json_path)
    #     JsonManager.compile_time_json_planning(irg)
    #     ingress_graph = irg.get_pipe("ingress")
    #     cfg = ControlFlowGraph._build_cfg(ingress_graph)
    #     ControlFlowGraph._get_aggregation(cfg)

    #     pipelets = JsonPlanner.get_pipelets(ingress_graph)
    #     print(set(pipelets))

    #     # for pipelet in pipelets:
    #     #     print("pipelet:", pipelet.root)
    #     # cfg_nodes = list(cfg.nodes())   # Root, Sink, MyIngress.tab2, MyIngress.tab1, node_2
    #     # topk_list = cfg_nodes[2].ir_nodes + cfg_nodes[3].ir_nodes
    #     # print("ir nodes:", cfg_nodes[2].ir_nodes[0])

    #     # assert len(pipelets) == 0
    #     group = ControlFlowGraph._get_topk_pipelet_groups(cfg, pipelets)
    #     print(group)
    #     assert len(group) == 0


@pytest.mark.parametrize(
    "json_path",
    [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "pipelet_pipelet_group", "test.p4.json")],
)
class TestPipeletGroup:
    @patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
    def test_topk_pipelet(self, retrieve_runtime_states, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")

        # setup probability
        tables = list(ingress_graph.tables)
        conds = list(ingress_graph.conditions)

        retrieve_runtime_states.return_value = utils.gen_runtime_stats(
            tables=tables, conds=conds, even_counter_distr=True
        )
        json_manager = JsonManager(api=RuntimeAPI())
        runtime_states = json_manager.retrieve_runtime_states(f"{round}_presplit_preopt.json")
        optimizer = Optimizer(api=RuntimeAPI(), sampling_period_us=1000000)
        optimizer._update_pipeline_stats(irg, runtime_states)

        pipelets = JsonPlanner.get_pipelets(ingress_graph)
        topk_pipelets = JsonPlanner.get_topk_pipelets(pipelets, 0.25, OptimizeTarget.LATENCY)
        assert len(topk_pipelets) == int(0.25 * len(pipelets)) == 4
        tp_names = [tp.root.name for tp in topk_pipelets]
        assert "MyIngress.tab01" in tp_names
        assert "MyIngress.tab09" in tp_names
        assert "MyIngress.tab_switch" in tp_names
        assert "MyIngress.tab02" in tp_names

    def test_single_pipelet(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        all_pipelets = JsonPlanner.get_pipelets(ingress_graph)
        all_pipelet_starts = {pipelet.root.name: pipelet for pipelet in all_pipelets}

        # test first table
        topk_pipelet_names: List[TableName] = []
        topk_pipelet_names.append("MyIngress.tab01")
        topk_pipelets = TestUtils.get_topk_pipelet(all_pipelets, topk_pipelet_names)

        pipelet_groups = JsonPlanner.get_pipelet_groups(ingress_graph, topk_pipelets, all_pipelets)
        pipelet_group_descs = [pg.desc for pg in pipelet_groups]
        expected_descs = [("MyIngress.tab01", "node_3", 1, [all_pipelet_starts["MyIngress.tab01"].desc])]
        assert pipelet_group_descs == expected_descs

        # test last table
        topk_pipelet_names.clear()
        topk_pipelet_names.append("MyIngress.tab17")
        topk_pipelets = TestUtils.get_topk_pipelet(all_pipelets, topk_pipelet_names)

        pipelet_groups = JsonPlanner.get_pipelet_groups(ingress_graph, topk_pipelets, all_pipelets)
        pipelet_group_descs = [pg.desc for pg in pipelet_groups]
        expected_descs = [("MyIngress.tab17", "Sink", 1, [all_pipelet_starts["MyIngress.tab17"].desc])]
        assert pipelet_group_descs == expected_descs

        # test switch table alone, should not be in any group
        topk_pipelet_names.clear()
        topk_pipelet_names.append("MyIngress.tab_switch")
        topk_pipelets = TestUtils.get_topk_pipelet(all_pipelets, topk_pipelet_names)

        pipelet_groups = JsonPlanner.get_pipelet_groups(ingress_graph, topk_pipelets, all_pipelets)
        pipelet_group_descs = [pg.desc for pg in pipelet_groups]
        assert pipelet_group_descs == []

        # pipelet inside if branch
        topk_pipelet_names.clear()
        topk_pipelet_names.append("MyIngress.tab02")
        topk_pipelets = TestUtils.get_topk_pipelet(all_pipelets, topk_pipelet_names)

        pipelet_groups = JsonPlanner.get_pipelet_groups(ingress_graph, topk_pipelets, all_pipelets)
        pipelet_group_descs = [pg.desc for pg in pipelet_groups]
        expected_descs = [("MyIngress.tab02", "node_6", 2, [all_pipelet_starts["MyIngress.tab02"].desc])]
        assert pipelet_group_descs == expected_descs

        # pipelet after if branch
        topk_pipelet_names.clear()
        topk_pipelet_names.append("MyIngress.tab08")
        topk_pipelets = TestUtils.get_topk_pipelet(all_pipelets, topk_pipelet_names)

        pipelet_groups = JsonPlanner.get_pipelet_groups(ingress_graph, topk_pipelets, all_pipelets)
        pipelet_group_descs = [pg.desc for pg in pipelet_groups]
        expected_descs = [("MyIngress.tab08", "MyIngress.tab09", 1, [all_pipelet_starts["MyIngress.tab08"].desc])]
        assert pipelet_group_descs == expected_descs

        # pipelet inside switch table
        topk_pipelet_names.clear()
        topk_pipelet_names.append("MyIngress.tab13")
        topk_pipelets = TestUtils.get_topk_pipelet(all_pipelets, topk_pipelet_names)

        pipelet_groups = JsonPlanner.get_pipelet_groups(ingress_graph, topk_pipelets, all_pipelets)
        pipelet_group_descs = [pg.desc for pg in pipelet_groups]
        expected_descs = [("MyIngress.tab13", "node_24", 1, [all_pipelet_starts["MyIngress.tab13"].desc])]
        assert pipelet_group_descs == expected_descs

        # pipelet before switch table
        topk_pipelet_names.clear()
        topk_pipelet_names.append("MyIngress.tab09")
        topk_pipelets = TestUtils.get_topk_pipelet(all_pipelets, topk_pipelet_names)

        pipelet_groups = JsonPlanner.get_pipelet_groups(ingress_graph, topk_pipelets, all_pipelets)
        pipelet_group_descs = [pg.desc for pg in pipelet_groups]
        expected_descs = [("MyIngress.tab09", "MyIngress.tab_switch", 2, [all_pipelet_starts["MyIngress.tab09"].desc])]
        assert pipelet_group_descs == expected_descs

    def test_discrete_single_pipelet(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        all_pipelets = JsonPlanner.get_pipelets(ingress_graph)
        all_pipelet_starts = {pipelet.root.name: pipelet for pipelet in all_pipelets}

        # test discrete pipelets in if-else branch
        topk_pipelet_names: List[TableName] = []
        topk_pipelet_names.append("MyIngress.tab14")
        topk_pipelet_names.append("MyIngress.tab15")
        topk_pipelet_names.append("MyIngress.tab16")
        topk_pipelets = TestUtils.get_topk_pipelet(all_pipelets, topk_pipelet_names)

        pipelet_groups = JsonPlanner.get_pipelet_groups(ingress_graph, topk_pipelets, all_pipelets)
        pipelet_group_descs = [pg.desc for pg in pipelet_groups]
        expected_descs = [
            ("MyIngress.tab14", "Sink", 1, [all_pipelet_starts["MyIngress.tab14"].desc]),
            ("MyIngress.tab15", "Sink", 1, [all_pipelet_starts["MyIngress.tab15"].desc]),
            ("MyIngress.tab16", "Sink", 1, [all_pipelet_starts["MyIngress.tab16"].desc]),
        ]
        assert sorted(pipelet_group_descs) == sorted(expected_descs)

        # test discrete pipelets in switch branch
        topk_pipelet_names: List[TableName] = []
        topk_pipelet_names.append("MyIngress.tab11")
        topk_pipelet_names.append("MyIngress.tab13")
        topk_pipelets = TestUtils.get_topk_pipelet(all_pipelets, topk_pipelet_names)

        pipelet_groups = JsonPlanner.get_pipelet_groups(ingress_graph, topk_pipelets, all_pipelets)
        pipelet_group_descs = [pg.desc for pg in pipelet_groups]
        expected_descs = [
            ("MyIngress.tab11", "node_24", 2, [all_pipelet_starts["MyIngress.tab11"].desc]),
            ("MyIngress.tab13", "node_24", 1, [all_pipelet_starts["MyIngress.tab13"].desc]),
        ]
        assert sorted(pipelet_group_descs) == sorted(expected_descs)

        # test before and after branch
        topk_pipelet_names: List[TableName] = []
        topk_pipelet_names.append("MyIngress.tab01")
        topk_pipelet_names.append("MyIngress.tab09")
        topk_pipelets = TestUtils.get_topk_pipelet(all_pipelets, topk_pipelet_names)

        pipelet_groups = JsonPlanner.get_pipelet_groups(ingress_graph, topk_pipelets, all_pipelets)
        pipelet_group_descs = [pg.desc for pg in pipelet_groups]
        expected_descs = [
            ("MyIngress.tab01", "node_3", 1, [all_pipelet_starts["MyIngress.tab01"].desc]),
            ("MyIngress.tab09", "MyIngress.tab_switch", 2, [all_pipelet_starts["MyIngress.tab09"].desc]),
        ]
        assert sorted(pipelet_group_descs) == sorted(expected_descs)

        # test before and after switch
        topk_pipelet_names: List[TableName] = []
        topk_pipelet_names.append("MyIngress.tab09")
        topk_pipelet_names.append("MyIngress.tab14")
        topk_pipelets = TestUtils.get_topk_pipelet(all_pipelets, topk_pipelet_names)

        pipelet_groups = JsonPlanner.get_pipelet_groups(ingress_graph, topk_pipelets, all_pipelets)
        pipelet_group_descs = [pg.desc for pg in pipelet_groups]
        expected_descs = [
            ("MyIngress.tab09", "MyIngress.tab_switch", 2, [all_pipelet_starts["MyIngress.tab09"].desc]),
            ("MyIngress.tab14", "Sink", 1, [all_pipelet_starts["MyIngress.tab14"].desc]),
        ]
        assert sorted(pipelet_group_descs) == sorted(expected_descs)

        # test multi discrete pipelets
        topk_pipelet_names: List[TableName] = []
        topk_pipelet_names.append("MyIngress.tab01")
        topk_pipelet_names.append("MyIngress.tab02")
        topk_pipelet_names.append("MyIngress.tab04")
        topk_pipelet_names.append("MyIngress.tab07")
        topk_pipelet_names.append("MyIngress.tab20")
        topk_pipelet_names.append("MyIngress.tab08")
        topk_pipelet_names.append("MyIngress.tab09")
        topk_pipelet_names.append("MyIngress.tab11")
        topk_pipelet_names.append("MyIngress.tab13")
        topk_pipelet_names.append("MyIngress.tab14")
        topk_pipelet_names.append("MyIngress.tab15")
        topk_pipelet_names.append("MyIngress.tab17")

        topk_pipelets = TestUtils.get_topk_pipelet(all_pipelets, topk_pipelet_names)

        pipelet_groups = JsonPlanner.get_pipelet_groups(ingress_graph, topk_pipelets, all_pipelets)
        pipelet_group_descs = [pg.desc for pg in pipelet_groups]
        expected_descs = [
            ("MyIngress.tab01", "node_3", 1, [all_pipelet_starts["MyIngress.tab01"].desc]),
            ("MyIngress.tab02", "node_6", 2, [all_pipelet_starts["MyIngress.tab02"].desc]),
            ("MyIngress.tab04", "node_9", 2, [all_pipelet_starts["MyIngress.tab04"].desc]),
            ("MyIngress.tab07", "node_12", 1, [all_pipelet_starts["MyIngress.tab07"].desc]),
            ("MyIngress.tab20", "MyIngress.tab08", 1, [all_pipelet_starts["MyIngress.tab20"].desc]),
            ("MyIngress.tab08", "MyIngress.tab09", 1, [all_pipelet_starts["MyIngress.tab08"].desc]),
            ("MyIngress.tab09", "MyIngress.tab_switch", 2, [all_pipelet_starts["MyIngress.tab09"].desc]),
            ("MyIngress.tab11", "node_24", 2, [all_pipelet_starts["MyIngress.tab11"].desc]),
            ("MyIngress.tab13", "node_24", 1, [all_pipelet_starts["MyIngress.tab13"].desc]),
            ("MyIngress.tab14", "Sink", 1, [all_pipelet_starts["MyIngress.tab14"].desc]),
            ("MyIngress.tab15", "Sink", 1, [all_pipelet_starts["MyIngress.tab15"].desc]),
            ("MyIngress.tab17", "Sink", 1, [all_pipelet_starts["MyIngress.tab17"].desc]),
        ]
        assert sorted(pipelet_group_descs) == sorted(expected_descs)

    def test_pipelet_merge(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        all_pipelets = JsonPlanner.get_pipelets(ingress_graph)
        all_pipelet_starts = {pipelet.root.name: pipelet for pipelet in all_pipelets}

        # test if-else branch merge
        topk_pipelet_names: List[TableName] = []
        topk_pipelet_names.append("MyIngress.tab16")
        topk_pipelet_names.append("MyIngress.tab17")
        topk_pipelets = TestUtils.get_topk_pipelet(all_pipelets, topk_pipelet_names)

        pipelet_groups = JsonPlanner.get_pipelet_groups(ingress_graph, topk_pipelets, all_pipelets)
        pipelet_group_descs = [pg.desc for pg in pipelet_groups]
        piplet_desc = [all_pipelet_starts[pipelet_name].desc for pipelet_name in topk_pipelet_names]
        expected_descs = [
            ("node_28", "Sink", len(topk_pipelet_names), piplet_desc),
        ]
        assert sorted(pipelet_group_descs) == sorted(expected_descs)

        # test if-else branch partial merge
        topk_pipelet_names: List[TableName] = []
        topk_pipelet_names.append("MyIngress.tab15")
        topk_pipelet_names.append("MyIngress.tab16")
        topk_pipelet_names.append("MyIngress.tab17")
        topk_pipelets = TestUtils.get_topk_pipelet(all_pipelets, topk_pipelet_names)

        pipelet_groups = JsonPlanner.get_pipelet_groups(ingress_graph, topk_pipelets, all_pipelets)
        pipelet_group_descs = [pg.desc for pg in pipelet_groups]
        piplet_desc = [all_pipelet_starts[pipelet_name].desc for pipelet_name in topk_pipelet_names]
        expected_descs = [
            ("node_26", "Sink", len(topk_pipelet_names), piplet_desc),
        ]
        assert sorted(pipelet_group_descs) == sorted(expected_descs)

        # TODO: test if branch alone merge
        # topk_pipelet_names.clear()
        # topk_pipelet_names.append("MyIngress.tab06")
        # topk_pipelets = TestUtils.get_topk_pipelet(all_pipelets, topk_pipelet_names)

        # pipelet_groups = JsonPlanner.get_pipelet_groups(ingress_graph, topk_pipelets, all_pipelets)
        # pipelet_group_descs = [pg.desc for pg in pipelet_groups]
        # piplet_desc = [
        #     all_pipelet_starts[pipelet_name].desc
        #     for pipelet_name in topk_pipelet_names
        # ]
        # expected_descs = [
        #     ('node_9', 'MyIngress.tab08', len(topk_pipelet_names), piplet_desc),
        # ]
        # assert sorted(pipelet_group_descs) == sorted(expected_descs)

        # TODO: test switch merge
        # topk_pipelet_names: List[TableName] = []
        # topk_pipelet_names.append("MyIngress.tab_switch")
        # topk_pipelet_names.append("MyIngress.tab11")
        # topk_pipelet_names.append("MyIngress.tab13")
        # topk_pipelet_names.append("MyIngress.tab21")
        # topk_pipelets = TestUtils.get_topk_pipelet(all_pipelets, topk_pipelet_names)

        # pipelet_groups = JsonPlanner.get_pipelet_groups(ingress_graph, topk_pipelets, all_pipelets)
        # pipelet_group_descs = [pg.desc for pg in pipelet_groups]
        # piplet_desc = [
        #     all_pipelet_starts[pipelet_name].desc
        #     for pipelet_name in topk_pipelet_names
        # ]
        # expected_descs = [
        #     ('MyIngress.tab_switch', 'node_24', len(topk_pipelet_names), piplet_desc),
        # ]
        # print(sorted(pipelet_group_descs))
        # print(sorted(expected_descs))
        # assert sorted(pipelet_group_descs) == sorted(expected_descs)

        # TODO: test nested branch merge
        # topk_pipelet_names.clear()
        # topk_pipelet_names.append("MyIngress.tab07")
        # topk_pipelet_names.append("MyIngress.tab18")
        # topk_pipelet_names.append("MyIngress.tab20")
        # topk_pipelets = TestUtils.get_topk_pipelet(all_pipelets, topk_pipelet_names)

        # pipelet_groups = JsonPlanner.get_pipelet_groups(ingress_graph, topk_pipelets, all_pipelets)
        # pipelet_group_descs = [pg.desc for pg in pipelet_groups]
        # piplet_desc = [
        #     all_pipelet_starts[pipelet_name].desc
        #     for pipelet_name in topk_pipelet_names
        # ]
        # expected_descs = [
        #     ('MyIngress.tab07', 'MyIngress.tab08', len(topk_pipelet_names), piplet_desc),
        # ]
        # print(sorted(pipelet_group_descs))
        # print(sorted(expected_descs))
        # assert sorted(pipelet_group_descs) == sorted(expected_descs)

        # TODO: test large merge
        # topk_pipelet_names.clear()
        # topk_pipelet_names.append("MyIngress.tab04")
        # topk_pipelet_names.append("MyIngress.tab06")
        # topk_pipelet_names.append("MyIngress.tab07")
        # topk_pipelet_names.append("MyIngress.tab18")
        # topk_pipelet_names.append("MyIngress.tab20")
        # topk_pipelets = TestUtils.get_topk_pipelet(all_pipelets, topk_pipelet_names)

        # pipelet_groups = JsonPlanner.get_pipelet_groups(ingress_graph, topk_pipelets, all_pipelets)
        # pipelet_group_descs = [pg.desc for pg in pipelet_groups]
        # piplet_desc = [
        #     all_pipelet_starts[pipelet_name].desc
        #     for pipelet_name in topk_pipelet_names
        # ]
        # expected_descs = [
        #     ('node_6', 'MyIngress.tab08', len(topk_pipelet_names), piplet_desc),
        # ]
        # print(sorted(pipelet_group_descs))
        # print(sorted(expected_descs))
        # assert sorted(pipelet_group_descs) == sorted(expected_descs)
