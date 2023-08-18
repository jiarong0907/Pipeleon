from copy import deepcopy
import math
from typing import Dict, List, Tuple
from graph_optimizer.algorithms import PipeletGroupOptimizer, PipeletOptimizer
from graph_optimizer.control_flow_graph import ControlFlowGraph
from graph_optimizer.options import GroupCacheOption, PipeletGroupOption, ProgramOption
from graph_optimizer.pipelet import Pipelet, PipeletGroup
from ir.condition import Condition
from ir.general_table import GeneralTable
from ir.table import Table
import pytest
import os
import mock_import
from runtime_CLI import RuntimeAPI
from unittest.mock import patch

from commons.constants import TOTAL_MEMORY, TOTAL_ENTRY_INSERTION, OptimizeMethod, OptimizeTarget
from commons.types import TableName
from graph_optimizer.graph_optimizer import Optimizer
from graph_optimizer.json_manager import JsonDeployer, JsonManager, JsonPlanner

import utils


def get_single_pipelet_option(retrieve_runtime_states, json_path, pipelet_root_name, enabled_methods):
    irg, target = JsonManager.retrieve_presplit(json_path)
    JsonManager.compile_time_json_planning(irg)
    ingress_graph = irg.get_pipe("ingress")
    tables = list(ingress_graph.tables)
    conds = list(ingress_graph.conditions)

    # Generate fake runtime profile and update probability
    retrieve_runtime_states.return_value = utils.gen_runtime_stats(tables=tables, conds=conds, even_counter_distr=True)
    json_manager = JsonManager(api=RuntimeAPI())
    runtime_states = json_manager.retrieve_runtime_states(f"{round}_presplit_preopt.json")
    optimizer = Optimizer(api=RuntimeAPI(), sampling_period_us=1000000)
    optimizer._update_pipeline_stats(irg, runtime_states)

    # Compute all optimization options
    pipelets = JsonPlanner.get_pipelets(ingress_graph)
    root_name_to_pipelet: Dict[TableName, Pipelet] = {}
    for pipelet in pipelets:
        root_name_to_pipelet[pipelet.root.name] = pipelet

    options = PipeletOptimizer._compute_all_options(root_name_to_pipelet[pipelet_root_name], enabled_methods)
    return options


@patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
class TestCache:
    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "optimized_perf", "cache_routing.p4.json"
            )
        ],
    )
    def test_cache_routing(self, retrieve_runtime_states, json_path):
        options = get_single_pipelet_option(
            retrieve_runtime_states, json_path, "sirius_ingress.routing", [OptimizeMethod.CACHE]
        )
        assert len(options) == 1
        assert math.isclose(options[0].lgain, 545, abs_tol=1)

    @pytest.mark.parametrize(
        "json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "consecutive_cache", "test.p4.json")],
    )
    def test_consecutive_cache(self, retrieve_runtime_states, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        conds = list(ingress_graph.conditions)

        # Generate fake runtime profile and update probability
        retrieve_runtime_states.return_value = utils.gen_runtime_stats(
            tables=tables, conds=conds, even_counter_distr=True
        )
        json_manager = JsonManager(api=RuntimeAPI())
        runtime_states = json_manager.retrieve_runtime_states(f"{round}_presplit_preopt.json")
        optimizer = Optimizer(api=RuntimeAPI(), sampling_period_us=1000000)
        optimizer._update_pipeline_stats(irg, runtime_states)

        # Compute all optimization options
        pipelets = JsonPlanner.get_pipelets(ingress_graph)
        root_name_to_pipelet: Dict[TableName, Pipelet] = {}
        for pipelet in pipelets:
            root_name_to_pipelet[pipelet.root.name] = pipelet

        options1 = PipeletOptimizer._compute_all_options(
            root_name_to_pipelet["MyIngress.tab02"], [OptimizeMethod.CACHE]
        )
        options2 = PipeletOptimizer._compute_all_options(
            root_name_to_pipelet["MyIngress.tab05"], [OptimizeMethod.CACHE]
        )

        program_option = ProgramOption([options1[0], options2[0]], 0)

        irgraph_pipe_copy = deepcopy(options1[0].irgraph_pipe)
        irgraph_pipe_copy2 = deepcopy(options1[0].irgraph_pipe)
        # re-split the original pipelet before we evaluate it
        JsonManager.from_plan_labeling_to_single_json(irgraph_pipe_copy.target, irgraph_pipe_copy.ir_graph)
        org_eval_metric = irgraph_pipe_copy.eval()
        utils.apply_pipelet_options(program_option.option, irgraph_pipe_copy2)
        JsonManager.from_plan_labeling_to_single_json(irgraph_pipe_copy2.target, irgraph_pipe_copy2.ir_graph)
        org_eval_metric = irgraph_pipe_copy2.eval()


@patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
class TestMerge:
    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "optimized_perf", "merge_direction.p4.json"
            )
        ],
    )
    def test_merge_direction(self, retrieve_runtime_states, json_path):
        options = get_single_pipelet_option(
            retrieve_runtime_states, json_path, "sirius_ingress.direction_lookup", [OptimizeMethod.MERGE]
        )
        assert len(options) == 1
        assert math.isclose(options[0].lgain, -50, abs_tol=1)


@patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
class TestReorder:
    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "optimized_perf", "reorder_acl.p4.json"
            )
        ],
    )
    def test_reorder_acl(self, retrieve_runtime_states, json_path):
        options = get_single_pipelet_option(
            retrieve_runtime_states, json_path, "sirius_ingress.direction_lookup", [OptimizeMethod.REORDER]
        )
        assert len(options) == 1
        assert math.isclose(options[0].lgain, 100, abs_tol=1)


@patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
class TestSoftcopy:
    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "optimized_perf", "softcopy_appliance.p4.json"
            )
        ],
    )
    def test_softcopy_appliance(self, retrieve_runtime_states, json_path):
        options = get_single_pipelet_option(
            retrieve_runtime_states, json_path, "sirius_ingress.acl_stage3", [OptimizeMethod.SOFTCOPY]
        )
        assert len(options) == 1
        assert math.isclose(options[0].lgain, 800, abs_tol=1)


@patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
class TestSoftmove:
    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "optimized_perf", "softmove_appliance.p4.json"
            )
        ],
    )
    def test_softmove_appliance(self, retrieve_runtime_states, json_path):
        options = get_single_pipelet_option(
            retrieve_runtime_states, json_path, "sirius_ingress.acl_stage3", [OptimizeMethod.SOFTMOVE]
        )
        assert len(options) == 1
        assert math.isclose(options[0].lgain, 1600, abs_tol=1)


@patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
class TestSimpleDash:
    @pytest.mark.parametrize(
        "json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "simple_dash", "test.p4.json")],
    )
    def test_cache_acl(self, retrieve_runtime_states, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        conds = list(ingress_graph.conditions)

        # Generate fake runtime profile and update probability
        retrieve_runtime_states.return_value = utils.gen_runtime_stats(tables, conds)
        json_manager = JsonManager(api=RuntimeAPI())
        runtime_states = json_manager.retrieve_runtime_states(f"{round}_presplit_preopt.json")
        optimizer = Optimizer(api=RuntimeAPI(), sampling_period_us=1000000)
        optimizer._update_pipeline_stats(irg, runtime_states)

        # Compute all optimization options
        pipelets = JsonPlanner.get_pipelets(ingress_graph)
        root_name_to_pipelet: Dict[TableName, Pipelet] = {}
        for pipelet in pipelets:
            root_name_to_pipelet[pipelet.root.name] = pipelet

        acl_pipelet = root_name_to_pipelet["sirius_ingress.acl_stage1"]
        options = PipeletOptimizer._compute_all_options(acl_pipelet, [OptimizeMethod.REORDER, OptimizeMethod.CACHE])
        for op in options:
            print(op)


@patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
class TestGroupCache:
    @classmethod
    def get_group_cache_option(cls, grp_options: List[PipeletGroupOption]) -> List[PipeletGroupOption]:
        res: List[PipeletGroupOption] = []
        for go in grp_options:
            if go.group_options != None:
                res.append(go)
        return res

    @classmethod
    def get_nodes_edges(cls, grp_option: PipeletGroupOption):
        original_pipe_grp = grp_option.pipelet_group
        pipe_grp_copy = deepcopy(original_pipe_grp)
        JsonPlanner.apply_group_cache(pipe_grp_copy)
        optimized_irg = pipe_grp_copy.irgraph_pipe.ir_graph
        JsonDeployer.prepare_optimizer_created_tables(optimized_irg)
        optimized_ingress_pipe = optimized_irg.get_pipe("ingress")
        nodes = cls.get_nodes(optimized_ingress_pipe)
        edges = cls.get_edges(optimized_ingress_pipe)
        return nodes, edges

    @classmethod
    def get_nodes(cls, irgraph_pipe):
        return [n.name for n in irgraph_pipe.nodes]

    @classmethod
    def get_edges(cls, irgraph_pipe):
        res = []
        for e in irgraph_pipe.edges:
            res.append((e[0].name, e[1].name))
        return res

    @classmethod
    def get_test_base_info(cls, retrieve_runtime_states, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        ControlFlowGraph._get_aggregation(cfg)
        tables = list(ingress_graph.tables)
        conds = list(ingress_graph.conditions)

        # Generate fake runtime profile and update probability
        retrieve_runtime_states.return_value = utils.gen_runtime_stats(tables, conds)
        json_manager = JsonManager(api=RuntimeAPI())
        runtime_states = json_manager.retrieve_runtime_states(f"{round}_presplit_preopt.json")
        optimizer = Optimizer(api=RuntimeAPI(), sampling_period_us=1000000)
        optimizer._update_pipeline_stats(irg, runtime_states)

        # Compute all optimization options
        pipelets = JsonPlanner.get_pipelets(ingress_graph)
        root_name_to_pipelet: Dict[TableName, Pipelet] = {}
        for pipelet in pipelets:
            root_name_to_pipelet[pipelet.root.name] = pipelet

        name_to_cond: Dict[str, Condition] = {}
        for co in conds:
            name_to_cond[co.name] = co
        name_to_tab: Dict[str, Table] = {}
        for t in tables:
            name_to_tab[t.name] = t

        return ingress_graph, pipelets, name_to_tab, name_to_cond, cfg

    @pytest.mark.parametrize(
        "json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "simple_cache_group", "test1.p4.json")],
    )
    def test_simple_group_cache_edge1(self, retrieve_runtime_states, json_path):
        ingress_graph, pipelets, name_to_tab, name_to_cond, cfg = self.get_test_base_info(
            retrieve_runtime_states, json_path
        )

        topk_pipelet_names = ["MyIngress.tab01", "MyIngress.tab02", "MyIngress.tab03", "MyIngress.tab04"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prg = PipeletGroup(
            irgraph_pipe=ingress_graph, root=name_to_cond["node_3"], sink=ingress_graph.sink, pipelets=topk_pipelets
        )
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prg, optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        assert len(grp_options) == 16
        grp_cache_op = self.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        nodes, edges = self.get_nodes_edges(grp_cache_op[0])
        assert "node_3$cch" in nodes
        assert ("MyIngress.tab05", "node_3$cch") in edges
        assert ("node_3$cch", "node_3") in edges
        assert ("node_3$cch", "Sink") in edges

    @pytest.mark.parametrize(
        "json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "simple_cache_group", "test1.p4.json")],
    )
    def test_simple_group_cache_edge2(self, retrieve_runtime_states, json_path):
        ingress_graph, pipelets, name_to_tab, name_to_cond, cfg = self.get_test_base_info(
            retrieve_runtime_states, json_path
        )

        topk_pipelet_names = [
            "MyIngress.tab01",
            "MyIngress.tab02",
            "MyIngress.tab03",
            "MyIngress.tab04",
            "MyIngress.tab05",
        ]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prg = PipeletGroup(
            irgraph_pipe=ingress_graph,
            root=name_to_tab["MyIngress.tab05"],
            sink=ingress_graph.sink,
            pipelets=topk_pipelets,
        )
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prg, optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        assert len(grp_options) == 32
        grp_cache_op = self.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        nodes, edges = self.get_nodes_edges(grp_cache_op[0])
        assert "MyIngress.tab05$cch" in nodes
        assert ("Root", "MyIngress.tab05$cch") in edges
        assert ("MyIngress.tab05$cch", "MyIngress.tab05") in edges
        assert ("MyIngress.tab05$cch", "Sink") in edges

    @pytest.mark.parametrize(
        "json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "simple_cache_group", "test2.p4.json")],
    )
    def test_simple_group_cache_edge3(self, retrieve_runtime_states, json_path):
        ingress_graph, pipelets, name_to_tab, name_to_cond, cfg = self.get_test_base_info(
            retrieve_runtime_states, json_path
        )

        topk_pipelet_names = ["MyIngress.tab01"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prg = PipeletGroup(
            irgraph_pipe=ingress_graph, root=name_to_cond["node_2"], sink=ingress_graph.sink, pipelets=topk_pipelets
        )
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prg, optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        assert len(grp_options) == 1
        grp_cache_op = self.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        nodes, edges = self.get_nodes_edges(grp_cache_op[0])
        assert "node_2$cch" in nodes
        assert ("Root", "node_2$cch") in edges
        assert ("node_2$cch", "node_2") in edges
        assert ("node_2$cch", "Sink") in edges

    @pytest.mark.parametrize(
        "json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "simple_cache_group", "test3.p4.json")],
    )
    def test_simple_group_cache_perf_with_drop(self, retrieve_runtime_states, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        cfg = ControlFlowGraph._build_cfg(ingress_graph)
        ControlFlowGraph._get_aggregation(cfg)
        tables = list(ingress_graph.tables)
        conds = list(ingress_graph.conditions)

        # Generate fake runtime profile and update probability
        retrieve_runtime_states.return_value = utils.gen_runtime_stats(tables, conds, True)
        json_manager = JsonManager(api=RuntimeAPI())
        runtime_states = json_manager.retrieve_runtime_states(f"{round}_presplit_preopt.json")
        optimizer = Optimizer(api=RuntimeAPI(), sampling_period_us=1000000)
        optimizer._update_pipeline_stats(irg, runtime_states)

        # Compute all optimization options
        pipelets = JsonPlanner.get_pipelets(ingress_graph)
        root_name_to_pipelet: Dict[TableName, Pipelet] = {}
        for pipelet in pipelets:
            root_name_to_pipelet[pipelet.root.name] = pipelet

        name_to_cond: Dict[str, Condition] = {}
        for co in conds:
            name_to_cond[co.name] = co
        name_to_tab: Dict[str, Table] = {}
        for t in tables:
            name_to_tab[t.name] = t

        topk_pipelet_names = ["MyIngress.tab01", "MyIngress.tab02", "MyIngress.tab03"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prgs = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelets)
        assert len(pipe_prgs) == 1
        assert pipe_prgs[0].root.name == "MyIngress.tab01"
        assert pipe_prgs[0].sink.name == "Sink"
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prgs[0], optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = TestGroupCache.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        nodes, edges = self.get_nodes_edges(grp_cache_op[0])
        assert "MyIngress.tab01$cch" in nodes
        assert ("Root", "MyIngress.tab01$cch") in edges
        assert ("MyIngress.tab01$cch", "MyIngress.tab01") in edges
        assert ("MyIngress.tab01$cch", "Sink") in edges

    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "pipelet_pipelet_group", "test.p4.json"
            )
        ],
    )
    def test_complex_group_cache_edge1(self, retrieve_runtime_states, json_path):
        ingress_graph, pipelets, name_to_tab, name_to_cond, cfg = self.get_test_base_info(
            retrieve_runtime_states, json_path
        )

        topk_pipelet_names = ["MyIngress.tab18", "MyIngress.tab19"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prg = PipeletGroup(
            irgraph_pipe=ingress_graph,
            root=name_to_cond["node_12"],
            sink=name_to_tab["MyIngress.tab20"],
            pipelets=topk_pipelets,
        )
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prg, optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = self.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        old_nodes = self.get_nodes(ingress_graph)
        old_edges = self.get_edges(ingress_graph)
        new_nodes, new_edges = self.get_nodes_edges(grp_cache_op[0])

        for node in old_nodes:
            assert node in new_nodes
        assert "node_12$cch" in new_nodes
        assert len(new_nodes) == len(old_nodes) + 1

        for edge in old_edges:
            if edge != ("MyIngress.tab07", "node_12"):
                assert edge in new_edges
        assert ("MyIngress.tab07", "node_12$cch") in new_edges
        assert ("node_12$cch", "node_12") in new_edges
        assert ("node_12$cch", "MyIngress.tab20") in new_edges
        assert ("MyIngress.tab07", "node_12") not in new_edges
        assert len(new_edges) == len(old_edges) + 2

        #####################################################
        ###################  Another test ###################
        #####################################################
        topk_pipelet_names = ["MyIngress.tab18", "MyIngress.tab19", "MyIngress.tab20"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prg = PipeletGroup(
            irgraph_pipe=ingress_graph,
            root=name_to_cond["node_12"],
            sink=name_to_tab["MyIngress.tab08"],
            pipelets=topk_pipelets,
        )
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prg, optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = self.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        old_nodes = self.get_nodes(ingress_graph)
        old_edges = self.get_edges(ingress_graph)
        new_nodes, new_edges = self.get_nodes_edges(grp_cache_op[0])

        for node in old_nodes:
            assert node in new_nodes
        assert "node_12$cch" in new_nodes
        assert len(new_nodes) == len(old_nodes) + 1

        for edge in old_edges:
            if edge != ("MyIngress.tab07", "node_12"):
                assert edge in new_edges
        assert ("MyIngress.tab07", "node_12$cch") in new_edges
        assert ("node_12$cch", "node_12") in new_edges
        assert ("node_12$cch", "MyIngress.tab08") in new_edges
        assert ("MyIngress.tab07", "node_12") not in new_edges
        assert len(new_edges) == len(old_edges) + 2

        #####################################################
        ###################  Another test ###################
        #####################################################
        topk_pipelet_names = ["MyIngress.tab07", "MyIngress.tab18", "MyIngress.tab19"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prg = PipeletGroup(
            irgraph_pipe=ingress_graph,
            root=name_to_tab["MyIngress.tab07"],
            sink=name_to_tab["MyIngress.tab20"],
            pipelets=topk_pipelets,
        )
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prg, optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = self.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        old_nodes = self.get_nodes(ingress_graph)
        old_edges = self.get_edges(ingress_graph)
        new_nodes, new_edges = self.get_nodes_edges(grp_cache_op[0])

        for node in old_nodes:
            assert node in new_nodes
        assert "MyIngress.tab07$cch" in new_nodes
        assert len(new_nodes) == len(old_nodes) + 1

        for edge in old_edges:
            if edge != ("node_6", "MyIngress.tab07"):
                assert edge in new_edges
        assert ("node_6", "MyIngress.tab07$cch") in new_edges
        assert ("MyIngress.tab07$cch", "MyIngress.tab07") in new_edges
        assert ("MyIngress.tab07$cch", "MyIngress.tab20") in new_edges
        assert ("node_6", "MyIngress.tab07") not in new_edges
        assert len(new_edges) == len(old_edges) + 2

        #####################################################
        ###################  Another test ###################
        #####################################################
        topk_pipelet_names = [
            "MyIngress.tab04",
            "MyIngress.tab05",
            "MyIngress.tab06",
            "MyIngress.tab07",
            "MyIngress.tab18",
            "MyIngress.tab19",
            "MyIngress.tab20",
        ]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prg = PipeletGroup(
            irgraph_pipe=ingress_graph,
            root=name_to_cond["node_6"],
            sink=name_to_tab["MyIngress.tab08"],
            pipelets=topk_pipelets,
        )
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prg, optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = self.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        old_nodes = self.get_nodes(ingress_graph)
        old_edges = self.get_edges(ingress_graph)
        new_nodes, new_edges = self.get_nodes_edges(grp_cache_op[0])

        for node in old_nodes:
            assert node in new_nodes
        assert "node_6$cch" in new_nodes
        assert len(new_nodes) == len(old_nodes) + 1

        for edge in old_edges:
            if edge != ("MyIngress.tab03", "node_6"):
                assert edge in new_edges
        assert ("MyIngress.tab03", "node_6$cch") in new_edges
        assert ("node_6$cch", "node_6") in new_edges
        assert ("node_6$cch", "MyIngress.tab08") in new_edges
        assert ("MyIngress.tab03", "node_6") not in new_edges
        assert len(new_edges) == len(old_edges) + 2

        #####################################################
        ###################  Another test ###################
        #####################################################
        topk_pipelet_names = ["MyIngress.tab14", "MyIngress.tab15", "MyIngress.tab16", "MyIngress.tab17"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prg = PipeletGroup(
            irgraph_pipe=ingress_graph, root=name_to_cond["node_24"], sink=ingress_graph.sink, pipelets=topk_pipelets
        )
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prg, optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = self.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        old_nodes = self.get_nodes(ingress_graph)
        old_edges = self.get_edges(ingress_graph)
        new_nodes, new_edges = self.get_nodes_edges(grp_cache_op[0])

        for node in old_nodes:
            assert node in new_nodes
        assert "node_24$cch" in new_nodes
        assert len(new_nodes) == len(old_nodes) + 1

        # for edge in old_edges:
        #     if edge != ("MyIngress.tab03", "node_24"):
        #         assert edge in new_edges
        assert ("MyIngress.tab21", "node_24$cch") in new_edges
        assert ("MyIngress.tab13", "node_24$cch") in new_edges
        assert ("MyIngress.tab12", "node_24$cch") in new_edges
        assert ("MyIngress.tab_switch", "node_24$cch") in new_edges
        assert ("node_24$cch", "node_24") in new_edges
        assert ("node_24$cch", "Sink") in new_edges

        assert ("MyIngress.tab21", "node_24") not in new_edges
        assert ("MyIngress.tab13", "node_24") not in new_edges
        assert ("MyIngress.tab12", "node_24") not in new_edges
        assert ("MyIngress.tab_switch", "node_24") not in new_edges
        assert len(new_edges) == len(old_edges) + 2

        #####################################################
        ###################  Another test ###################
        #####################################################
        topk_pipelet_names = ["MyIngress.tab06"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prg = PipeletGroup(
            irgraph_pipe=ingress_graph,
            root=name_to_cond["node_9"],
            sink=name_to_tab["MyIngress.tab08"],
            pipelets=topk_pipelets,
        )
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prg, optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = self.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        old_nodes = self.get_nodes(ingress_graph)
        old_edges = self.get_edges(ingress_graph)
        new_nodes, new_edges = self.get_nodes_edges(grp_cache_op[0])

        for node in old_nodes:
            assert node in new_nodes
        assert "node_9$cch" in new_nodes
        assert len(new_nodes) == len(old_nodes) + 1

        for edge in old_edges:
            if edge != ("MyIngress.tab05", "node_9"):
                assert edge in new_edges
        assert ("MyIngress.tab05", "node_9$cch") in new_edges
        assert ("node_9$cch", "node_9") in new_edges
        assert ("node_9$cch", "MyIngress.tab08") in new_edges
        assert ("MyIngress.tab05", "node_9") not in new_edges
        assert len(new_edges) == len(old_edges) + 2

        #####################################################
        ###################  Another test ###################
        #####################################################
        topk_pipelet_names = [
            "MyIngress.tab02",
            "MyIngress.tab03",
            "MyIngress.tab04",
            "MyIngress.tab05",
            "MyIngress.tab06",
            "MyIngress.tab07",
            "MyIngress.tab08",
            "MyIngress.tab18",
            "MyIngress.tab19",
            "MyIngress.tab20",
        ]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prg = PipeletGroup(
            irgraph_pipe=ingress_graph,
            root=name_to_cond["node_3"],
            sink=name_to_tab["MyIngress.tab09"],
            pipelets=topk_pipelets,
        )
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prg, optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = self.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        old_nodes = self.get_nodes(ingress_graph)
        old_edges = self.get_edges(ingress_graph)
        new_nodes, new_edges = self.get_nodes_edges(grp_cache_op[0])

        for node in old_nodes:
            assert node in new_nodes
        assert "node_3$cch" in new_nodes
        assert len(new_nodes) == len(old_nodes) + 1

        for edge in old_edges:
            if edge != ("MyIngress.tab01", "node_3"):
                assert edge in new_edges
        assert ("MyIngress.tab01", "node_3$cch") in new_edges
        assert ("node_3$cch", "node_3") in new_edges
        assert ("node_3$cch", "MyIngress.tab09") in new_edges
        assert ("MyIngress.tab01", "node_3") not in new_edges
        assert len(new_edges) == len(old_edges) + 2

        #####################################################
        ###################  Another test ###################
        #####################################################
        topk_pipelet_names = ["MyIngress.tab16", "MyIngress.tab17"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prg = PipeletGroup(
            irgraph_pipe=ingress_graph, root=name_to_cond["node_28"], sink=ingress_graph.sink, pipelets=topk_pipelets
        )
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prg, optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = self.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        old_nodes = self.get_nodes(ingress_graph)
        old_edges = self.get_edges(ingress_graph)
        new_nodes, new_edges = self.get_nodes_edges(grp_cache_op[0])

        for node in old_nodes:
            assert node in new_nodes
        assert "node_28$cch" in new_nodes
        assert len(new_nodes) == len(old_nodes) + 1

        for edge in old_edges:
            if edge != ("node_26", "node_28"):
                assert edge in new_edges
        assert ("node_26", "node_28$cch") in new_edges
        assert ("node_28$cch", "node_28") in new_edges
        assert ("node_28$cch", "Sink") in new_edges
        assert ("node_26", "node_28") not in new_edges
        assert len(new_edges) == len(old_edges) + 2

        #####################################################
        ###################  Another test ###################
        #####################################################
        topk_pipelet_names = ["MyIngress.tab15", "MyIngress.tab16", "MyIngress.tab17"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prg = PipeletGroup(
            irgraph_pipe=ingress_graph, root=name_to_cond["node_26"], sink=ingress_graph.sink, pipelets=topk_pipelets
        )
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prg, optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = self.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        old_nodes = self.get_nodes(ingress_graph)
        old_edges = self.get_edges(ingress_graph)
        new_nodes, new_edges = self.get_nodes_edges(grp_cache_op[0])

        for node in old_nodes:
            assert node in new_nodes
        assert "node_26$cch" in new_nodes
        assert len(new_nodes) == len(old_nodes) + 1

        for edge in old_edges:
            if edge != ("node_24", "node_26"):
                assert edge in new_edges
        assert ("node_24", "node_26$cch") in new_edges
        assert ("node_26$cch", "node_26") in new_edges
        assert ("node_26$cch", "Sink") in new_edges
        assert ("node_24", "node_26") not in new_edges
        assert len(new_edges) == len(old_edges) + 2

        #####################################################
        ###################  Another test ###################
        #####################################################
        topk_pipelet_names = ["MyIngress.tab09", "MyIngress.tab10"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prg = PipeletGroup(
            irgraph_pipe=ingress_graph,
            root=name_to_tab["MyIngress.tab09"],
            sink=name_to_tab["MyIngress.tab_switch"],
            pipelets=topk_pipelets,
        )
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prg, optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = self.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        old_nodes = self.get_nodes(ingress_graph)
        old_edges = self.get_edges(ingress_graph)
        new_nodes, new_edges = self.get_nodes_edges(grp_cache_op[0])

        for node in old_nodes:
            assert node in new_nodes
        assert "MyIngress.tab09$cch" in new_nodes
        assert len(new_nodes) == len(old_nodes) + 1

        for edge in old_edges:
            if edge != ("node_3", "MyIngress.tab09") and edge != ("MyIngress.tab08", "MyIngress.tab09"):
                assert edge in new_edges
        assert ("node_3", "MyIngress.tab09$cch") in new_edges
        assert ("MyIngress.tab08", "MyIngress.tab09$cch") in new_edges
        assert ("MyIngress.tab09$cch", "MyIngress.tab09") in new_edges
        assert ("MyIngress.tab09$cch", "MyIngress.tab_switch") in new_edges
        assert ("node_3", "MyIngress.tab09") not in new_edges
        assert ("MyIngress.tab08", "MyIngress.tab09") not in new_edges
        assert len(new_edges) == len(old_edges) + 2


@patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
class TestGroupCacheCFG:
    @pytest.mark.parametrize(
        "json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "simple_cache_group", "test1.p4.json")],
    )
    def test_simple_group_cache_edge1(self, retrieve_runtime_states, json_path):
        ingress_graph, pipelets, name_to_tab, name_to_cond, cfg = TestGroupCache.get_test_base_info(
            retrieve_runtime_states, json_path
        )

        topk_pipelet_names = ["MyIngress.tab01", "MyIngress.tab02", "MyIngress.tab03", "MyIngress.tab04"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prgs = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelets)
        assert len(pipe_prgs) == 1
        assert pipe_prgs[0].root.name == "node_3"
        assert pipe_prgs[0].sink.name == "Sink"
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prgs[0], optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        assert len(grp_options) == 16
        grp_cache_op = TestGroupCache.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        nodes, edges = TestGroupCache.get_nodes_edges(grp_cache_op[0])
        assert "node_3$cch" in nodes
        assert ("MyIngress.tab05", "node_3$cch") in edges
        assert ("node_3$cch", "node_3") in edges
        assert ("node_3$cch", "Sink") in edges

    @pytest.mark.parametrize(
        "json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "simple_cache_group", "test1.p4.json")],
    )
    def test_simple_group_cache_edge2(self, retrieve_runtime_states, json_path):
        ingress_graph, pipelets, name_to_tab, name_to_cond, cfg = TestGroupCache.get_test_base_info(
            retrieve_runtime_states, json_path
        )

        topk_pipelet_names = [
            "MyIngress.tab01",
            "MyIngress.tab02",
            "MyIngress.tab03",
            "MyIngress.tab04",
            "MyIngress.tab05",
        ]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prgs = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelets)
        assert len(pipe_prgs) == 1
        assert pipe_prgs[0].root.name == "MyIngress.tab05"
        assert pipe_prgs[0].sink.name == "Sink"
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prgs[0], optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        assert len(grp_options) == 32
        grp_cache_op = TestGroupCache.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        nodes, edges = TestGroupCache.get_nodes_edges(grp_cache_op[0])
        assert "MyIngress.tab05$cch" in nodes
        assert ("Root", "MyIngress.tab05$cch") in edges
        assert ("MyIngress.tab05$cch", "MyIngress.tab05") in edges
        assert ("MyIngress.tab05$cch", "Sink") in edges

    @pytest.mark.parametrize(
        "json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "simple_cache_group", "test2.p4.json")],
    )
    def test_simple_group_cache_edge3(self, retrieve_runtime_states, json_path):
        ingress_graph, pipelets, name_to_tab, name_to_cond, cfg = TestGroupCache.get_test_base_info(
            retrieve_runtime_states, json_path
        )

        topk_pipelet_names = ["MyIngress.tab01"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prgs = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelets)
        assert len(pipe_prgs) == 1
        assert pipe_prgs[0].root.name == "node_2"
        assert pipe_prgs[0].sink.name == "Sink"
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prgs[0], optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        assert len(grp_options) == 1
        grp_cache_op = TestGroupCache.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        nodes, edges = TestGroupCache.get_nodes_edges(grp_cache_op[0])
        assert "node_2$cch" in nodes
        assert ("Root", "node_2$cch") in edges
        assert ("node_2$cch", "node_2") in edges
        assert ("node_2$cch", "Sink") in edges

    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "pipelet_pipelet_group", "test.p4.json"
            )
        ],
    )
    def test_complex_group_cache_edge1(self, retrieve_runtime_states, json_path):
        ingress_graph, pipelets, name_to_tab, name_to_cond, cfg = TestGroupCache.get_test_base_info(
            retrieve_runtime_states, json_path
        )

        topk_pipelet_names = ["MyIngress.tab18", "MyIngress.tab19"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prgs = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelets)
        assert len(pipe_prgs) == 1
        assert pipe_prgs[0].root.name == "MyIngress.tab18"
        assert pipe_prgs[0].sink.name == "MyIngress.tab20"
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prgs[0], optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = TestGroupCache.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        old_nodes = TestGroupCache.get_nodes(ingress_graph)
        old_edges = TestGroupCache.get_edges(ingress_graph)
        new_nodes, new_edges = TestGroupCache.get_nodes_edges(grp_cache_op[0])

        for node in old_nodes:
            assert node in new_nodes
        assert "MyIngress.tab18$cch" in new_nodes
        assert len(new_nodes) == len(old_nodes) + 1

        for edge in old_edges:
            if edge != ("node_12", "MyIngress.tab18"):
                assert edge in new_edges
        assert ("node_12", "MyIngress.tab18$cch") in new_edges
        assert ("MyIngress.tab18$cch", "MyIngress.tab18") in new_edges
        assert ("MyIngress.tab18$cch", "MyIngress.tab20") in new_edges
        assert ("node_12", "MyIngress.tab18") not in new_edges
        assert len(new_edges) == len(old_edges) + 2

        #####################################################
        ###################  Another test ###################
        #####################################################
        ingress_graph, pipelets, name_to_tab, name_to_cond, cfg = TestGroupCache.get_test_base_info(
            retrieve_runtime_states, json_path
        )
        topk_pipelet_names = ["MyIngress.tab18", "MyIngress.tab19", "MyIngress.tab20"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prgs = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelets)
        assert len(pipe_prgs) == 1
        assert pipe_prgs[0].root.name == "node_12"
        assert pipe_prgs[0].sink.name == "MyIngress.tab08"
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prgs[0], optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = TestGroupCache.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        old_nodes = TestGroupCache.get_nodes(ingress_graph)
        old_edges = TestGroupCache.get_edges(ingress_graph)
        new_nodes, new_edges = TestGroupCache.get_nodes_edges(grp_cache_op[0])

        for node in old_nodes:
            assert node in new_nodes
        assert "node_12$cch" in new_nodes
        assert len(new_nodes) == len(old_nodes) + 1

        for edge in old_edges:
            if edge != ("MyIngress.tab07", "node_12"):
                assert edge in new_edges
        assert ("MyIngress.tab07", "node_12$cch") in new_edges
        assert ("node_12$cch", "node_12") in new_edges
        assert ("node_12$cch", "MyIngress.tab08") in new_edges
        assert ("MyIngress.tab07", "node_12") not in new_edges
        assert len(new_edges) == len(old_edges) + 2

        #####################################################
        ###################  Another test ###################
        #####################################################
        ingress_graph, pipelets, name_to_tab, name_to_cond, cfg = TestGroupCache.get_test_base_info(
            retrieve_runtime_states, json_path
        )
        topk_pipelet_names = ["MyIngress.tab07", "MyIngress.tab18", "MyIngress.tab19"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prgs = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelets)
        assert len(pipe_prgs) == 2
        if pipe_prgs[0].root.name == "MyIngress.tab07":
            assert pipe_prgs[0].sink.name == "node_12"
            assert pipe_prgs[1].root.name == "MyIngress.tab18"
            assert pipe_prgs[1].sink.name == "MyIngress.tab20"
        elif pipe_prgs[0].root.name == "MyIngress.tab18":
            assert pipe_prgs[0].sink.name == "tab20"
            assert pipe_prgs[1].root.name == "MyIngress.tab07"
            assert pipe_prgs[1].sink.name == "node_12"
        else:
            assert False

        #####################################################
        ###################  Another test ###################
        #####################################################
        ingress_graph, pipelets, name_to_tab, name_to_cond, cfg = TestGroupCache.get_test_base_info(
            retrieve_runtime_states, json_path
        )
        topk_pipelet_names = ["MyIngress.tab07", "MyIngress.tab18", "MyIngress.tab19", "MyIngress.tab20"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prgs = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelets)
        assert len(pipe_prgs) == 1
        assert pipe_prgs[0].root.name == "MyIngress.tab07"
        assert pipe_prgs[0].sink.name == "MyIngress.tab08"

        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prgs[0], optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = TestGroupCache.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        old_nodes = TestGroupCache.get_nodes(ingress_graph)
        old_edges = TestGroupCache.get_edges(ingress_graph)
        new_nodes, new_edges = TestGroupCache.get_nodes_edges(grp_cache_op[0])

        for node in old_nodes:
            assert node in new_nodes
        assert "MyIngress.tab07$cch" in new_nodes
        assert len(new_nodes) == len(old_nodes) + 1

        for edge in old_edges:
            if edge != ("node_6", "MyIngress.tab07"):
                assert edge in new_edges
        assert ("node_6", "MyIngress.tab07$cch") in new_edges
        assert ("MyIngress.tab07$cch", "MyIngress.tab07") in new_edges
        assert ("MyIngress.tab07$cch", "MyIngress.tab08") in new_edges
        assert ("node_6", "MyIngress.tab07") not in new_edges
        assert len(new_edges) == len(old_edges) + 2

        #####################################################
        ###################  Another test ###################
        #####################################################
        ingress_graph, pipelets, name_to_tab, name_to_cond, cfg = TestGroupCache.get_test_base_info(
            retrieve_runtime_states, json_path
        )

        topk_pipelet_names = ["MyIngress.tab14", "MyIngress.tab15", "MyIngress.tab16", "MyIngress.tab17"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prgs = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelets)

        assert len(pipe_prgs) == 1
        assert pipe_prgs[0].root.name == "node_24"
        assert pipe_prgs[0].sink.name == "Sink"
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prgs[0], optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = TestGroupCache.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        old_nodes = TestGroupCache.get_nodes(ingress_graph)
        old_edges = TestGroupCache.get_edges(ingress_graph)
        new_nodes, new_edges = TestGroupCache.get_nodes_edges(grp_cache_op[0])

        for node in old_nodes:
            assert node in new_nodes
        assert "node_24$cch" in new_nodes
        assert len(new_nodes) == len(old_nodes) + 1

        # for edge in old_edges:
        #     if edge != ("MyIngress.tab03", "node_24"):
        #         assert edge in new_edges
        assert ("MyIngress.tab21", "node_24$cch") in new_edges
        assert ("MyIngress.tab13", "node_24$cch") in new_edges
        assert ("MyIngress.tab12", "node_24$cch") in new_edges
        assert ("MyIngress.tab_switch", "node_24$cch") in new_edges
        assert ("node_24$cch", "node_24") in new_edges
        assert ("node_24$cch", "Sink") in new_edges

        assert ("MyIngress.tab21", "node_24") not in new_edges
        assert ("MyIngress.tab13", "node_24") not in new_edges
        assert ("MyIngress.tab12", "node_24") not in new_edges
        assert ("MyIngress.tab_switch", "node_24") not in new_edges
        assert len(new_edges) == len(old_edges) + 2

        #####################################################
        ###################  Another test ###################
        #####################################################
        ingress_graph, pipelets, name_to_tab, name_to_cond, cfg = TestGroupCache.get_test_base_info(
            retrieve_runtime_states, json_path
        )
        topk_pipelet_names = ["MyIngress.tab06"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prgs = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelets)

        assert len(pipe_prgs) == 1
        assert pipe_prgs[0].root.name == "MyIngress.tab06"
        assert pipe_prgs[0].sink.name == "MyIngress.tab08"
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prgs[0], optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = TestGroupCache.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        old_nodes = TestGroupCache.get_nodes(ingress_graph)
        old_edges = TestGroupCache.get_edges(ingress_graph)
        new_nodes, new_edges = TestGroupCache.get_nodes_edges(grp_cache_op[0])

        for node in old_nodes:
            assert node in new_nodes
        assert "MyIngress.tab06$cch" in new_nodes
        assert len(new_nodes) == len(old_nodes) + 1

        for edge in old_edges:
            if edge != ("node_9", "MyIngress.tab06"):
                assert edge in new_edges
        assert ("node_9", "MyIngress.tab06$cch") in new_edges
        assert ("MyIngress.tab06$cch", "MyIngress.tab06") in new_edges
        assert ("MyIngress.tab06$cch", "MyIngress.tab08") in new_edges
        assert ("node_9", "MyIngress.tab06") not in new_edges
        assert len(new_edges) == len(old_edges) + 2

        #####################################################
        ###################  Another test ###################
        #####################################################
        ingress_graph, pipelets, name_to_tab, name_to_cond, cfg = TestGroupCache.get_test_base_info(
            retrieve_runtime_states, json_path
        )
        topk_pipelet_names = [
            "MyIngress.tab02",
            "MyIngress.tab04",
            "MyIngress.tab06",
            "MyIngress.tab07",
            "MyIngress.tab08",
            "MyIngress.tab18",
            "MyIngress.tab20",
            "MyIngress.tab09",
        ]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prgs = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelets)
        assert len(pipe_prgs) == 1
        assert pipe_prgs[0].root.name == "node_3"
        assert pipe_prgs[0].sink.name == "MyIngress.tab_switch"
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prgs[0], optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = TestGroupCache.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        old_nodes = TestGroupCache.get_nodes(ingress_graph)
        old_edges = TestGroupCache.get_edges(ingress_graph)
        new_nodes, new_edges = TestGroupCache.get_nodes_edges(grp_cache_op[0])

        for node in old_nodes:
            assert node in new_nodes
        assert "node_3$cch" in new_nodes
        assert len(new_nodes) == len(old_nodes) + 1

        for edge in old_edges:
            if edge != ("MyIngress.tab01", "node_3"):
                assert edge in new_edges
        assert ("MyIngress.tab01", "node_3$cch") in new_edges
        assert ("node_3$cch", "node_3") in new_edges
        assert ("node_3$cch", "MyIngress.tab_switch") in new_edges
        assert ("MyIngress.tab01", "node_3") not in new_edges
        assert len(new_edges) == len(old_edges) + 2

        # #####################################################
        # ###################  Another test ###################
        # #####################################################
        ingress_graph, pipelets, name_to_tab, name_to_cond, cfg = TestGroupCache.get_test_base_info(
            retrieve_runtime_states, json_path
        )
        topk_pipelet_names = ["MyIngress.tab16", "MyIngress.tab17"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prgs = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelets)

        assert len(pipe_prgs) == 1
        assert pipe_prgs[0].root.name == "node_28"
        assert pipe_prgs[0].sink.name == "Sink"
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prgs[0], optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = TestGroupCache.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        old_nodes = TestGroupCache.get_nodes(ingress_graph)
        old_edges = TestGroupCache.get_edges(ingress_graph)
        new_nodes, new_edges = TestGroupCache.get_nodes_edges(grp_cache_op[0])

        for node in old_nodes:
            assert node in new_nodes
        assert "node_28$cch" in new_nodes
        assert len(new_nodes) == len(old_nodes) + 1

        for edge in old_edges:
            if edge != ("node_26", "node_28"):
                assert edge in new_edges
        assert ("node_26", "node_28$cch") in new_edges
        assert ("node_28$cch", "node_28") in new_edges
        assert ("node_28$cch", "Sink") in new_edges
        assert ("node_26", "node_28") not in new_edges
        assert len(new_edges) == len(old_edges) + 2

        # #####################################################
        # ###################  Another test ###################
        # #####################################################
        ingress_graph, pipelets, name_to_tab, name_to_cond, cfg = TestGroupCache.get_test_base_info(
            retrieve_runtime_states, json_path
        )
        topk_pipelet_names = ["MyIngress.tab15", "MyIngress.tab16", "MyIngress.tab17"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prgs = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelets)

        assert len(pipe_prgs) == 1
        assert pipe_prgs[0].root.name == "node_26"
        assert pipe_prgs[0].sink.name == "Sink"
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prgs[0], optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = TestGroupCache.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        old_nodes = TestGroupCache.get_nodes(ingress_graph)
        old_edges = TestGroupCache.get_edges(ingress_graph)
        new_nodes, new_edges = TestGroupCache.get_nodes_edges(grp_cache_op[0])

        for node in old_nodes:
            assert node in new_nodes
        assert "node_26$cch" in new_nodes
        assert len(new_nodes) == len(old_nodes) + 1

        for edge in old_edges:
            if edge != ("node_24", "node_26"):
                assert edge in new_edges
        assert ("node_24", "node_26$cch") in new_edges
        assert ("node_26$cch", "node_26") in new_edges
        assert ("node_26$cch", "Sink") in new_edges
        assert ("node_24", "node_26") not in new_edges
        assert len(new_edges) == len(old_edges) + 2

        # #####################################################
        # ###################  Another test ###################
        # #####################################################
        ingress_graph, pipelets, name_to_tab, name_to_cond, cfg = TestGroupCache.get_test_base_info(
            retrieve_runtime_states, json_path
        )
        topk_pipelet_names = ["MyIngress.tab09", "MyIngress.tab10"]
        topk_pipelets = utils.get_topk_pipelet(pipelets, topk_pipelet_names)
        pipe_prgs = ControlFlowGraph._get_topk_pipelet_groups(ingress_graph, cfg, topk_pipelets)

        assert len(pipe_prgs) == 1
        assert pipe_prgs[0].root.name == "MyIngress.tab09"
        assert pipe_prgs[0].sink.name == "MyIngress.tab_switch"
        grp_options = PipeletGroupOptimizer._compute_all_options(
            pipe_grp=pipe_prgs[0], optimize_method=[OptimizeMethod.REORDER, OptimizeMethod.CACHE, OptimizeMethod.MERGE]
        )
        # assert len(grp_options) == 1
        grp_cache_op = TestGroupCache.get_group_cache_option(grp_options)
        assert len(grp_cache_op) == 1

        old_nodes = TestGroupCache.get_nodes(ingress_graph)
        old_edges = TestGroupCache.get_edges(ingress_graph)
        new_nodes, new_edges = TestGroupCache.get_nodes_edges(grp_cache_op[0])

        for node in old_nodes:
            assert node in new_nodes
        assert "MyIngress.tab09$cch" in new_nodes
        assert len(new_nodes) == len(old_nodes) + 1

        for edge in old_edges:
            if edge != ("node_3", "MyIngress.tab09") and edge != ("MyIngress.tab08", "MyIngress.tab09"):
                assert edge in new_edges
        assert ("node_3", "MyIngress.tab09$cch") in new_edges
        assert ("MyIngress.tab08", "MyIngress.tab09$cch") in new_edges
        assert ("MyIngress.tab09$cch", "MyIngress.tab09") in new_edges
        assert ("MyIngress.tab09$cch", "MyIngress.tab_switch") in new_edges
        assert ("node_3", "MyIngress.tab09") not in new_edges
        assert ("MyIngress.tab08", "MyIngress.tab09") not in new_edges
        assert len(new_edges) == len(old_edges) + 2
