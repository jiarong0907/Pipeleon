import pytest
import os, sys, random, json
import mock_import
import tempfile
from deepdiff import DeepDiff
import networkx as nx

from graph_optimizer.options import *
from ir.irgraph import IrGraph
from ir.match_key import MatchType
from graph_optimizer.json_manager import JsonManager, JsonPlanner
from commons.constants import OptimizedType
import utils


class TestApplyOptions:
    def test_apply_reorder(self):
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        original_table_names = [t.name for t in pipelet.tables]
        new_order = [0, 2, 1]
        ro = ReorderOption(new_order)
        JsonPlanner.apply_reordering(pipelet, ro)
        new_table_names = [t.name for t in pipelet.tables]

        for i in range(len(new_order)):
            assert original_table_names[i] == new_table_names[new_order[i]]

    def test_apply_reorder_random(self):
        for _ in range(100):
            num_tables = random.randint(2, 10)
            pipelet = utils.create_pipelet(num_tables, MatchType.TERNARY)
            original_table_names = [t.name for t in pipelet.tables]
            new_order = list(range(0, num_tables))
            random.shuffle(new_order)
            ro = ReorderOption(new_order)
            JsonPlanner.apply_reordering(pipelet, ro)
            new_table_names = [t.name for t in pipelet.tables]

            for i in range(len(new_order)):
                assert original_table_names[new_order[i]] == new_table_names[i]


class TestJsonLoad:
    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "simple_test_no_const_action", "test.p4.json"
            ),
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "real_world", "switch.p4.json"),
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "real_world", "fabric.p4.json"),
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "synthesized", "prog_0.p4.json"),
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "real_world", "dash", "test.p4.json"),
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "simple_dash", "test.p4.json"),
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "real_world", "l2l3_acl", "test.p4.json"
            ),
        ],
    )
    def test_read_json(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        pipelets = JsonPlanner.get_pipelets(ingress_graph)
        print(len(pipelets))
        for p in pipelets:
            print([t for t in p.table_names])


class TestJsonIrTransform:
    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "simple_test_no_const_action", "test.p4.json"
            ),
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "simple_dash", "test.p4.json"),
        ],
    )
    def test_json_read_write(self, json_path):
        irg = IrGraph.import_p4cirjson(path=json_path)
        tmp_file = tempfile.NamedTemporaryFile()
        irg.export_p4cirjson(tmp_file.name)

        with open(json_path, "r") as f:
            original = json.load(f)

        with open(tmp_file.name, "r") as f:
            exported = json.load(f)

        diff = DeepDiff(
            original,
            exported,
            # ignore the source info in json
            exclude_regex_paths={r"root(.*?)\['source_info'\]"},
        )
        assert len(diff) == 0

        irg_exported = IrGraph.import_p4cirjson(path=tmp_file.name)
        for imp_pipe in irg._ir_pipelines:
            matched = False
            for exp_pipe in irg_exported._ir_pipelines:
                if imp_pipe.ancor_point == exp_pipe.ancor_point:
                    assert nx.is_isomorphic(imp_pipe, exp_pipe)
                    matched = True
            assert matched, f"Pipe {imp_pipe.ancor_point} was not found in exported graph"


@pytest.mark.parametrize(
    "json_path",
    [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "semi_support_unsupport", "test.p4.json")],
)
class TestCompileTimeJsonPlanning:
    def test_mark_unsupported_nodes(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        JsonPlanner.mark_unsupported_nodes(irg)

        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        unspt_tab1 = tables[0]
        unspt_tab2 = tables[1]
        unspt_tab3 = tables[2]
        unspt_tab4 = tables[3]
        unspt_tab5 = tables[4]
        spt_tab = tables[8]

        assert unspt_tab1.optimized_type == OptimizedType.SW_STEERING
        assert unspt_tab2.optimized_type == OptimizedType.SW_STEERING
        assert unspt_tab3.optimized_type == OptimizedType.SW_STEERING
        assert unspt_tab4.optimized_type == OptimizedType.SW_STEERING
        assert unspt_tab5.optimized_type == OptimizedType.SW_STEERING
        assert spt_tab.optimized_type == OptimizedType.HW_STEERING

    def test_mark_semisupported_nodes(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        JsonPlanner.mark_semisupported_nodes(irg)

        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        semispttab1 = tables[5]
        semispttab2 = tables[6]
        semispttab3 = tables[7]
        spt_tab = tables[8]

        assert semispttab1.optimized_type == OptimizedType.SW_STEERING
        assert semispttab2.optimized_type == OptimizedType.SEMI_SUPPORTED
        assert semispttab3.optimized_type == OptimizedType.SEMI_SUPPORTED
        assert spt_tab.optimized_type == OptimizedType.HW_STEERING

    def test_mark_unsupported_semisupported(self, json_path):
        """mark_unsupported_nodes first,
        then mark_semisupported_nodes
        """
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)

        JsonPlanner.mark_unsupported_nodes(irg)
        JsonPlanner.mark_semisupported_nodes(irg)

        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        unspt_tab1 = tables[0]
        unspt_tab2 = tables[1]
        unspt_tab3 = tables[2]
        unspt_tab4 = tables[3]
        unspt_tab5 = tables[4]
        semispttab1 = tables[5]
        semispttab2 = tables[6]
        semispttab3 = tables[7]
        spt_tab = tables[8]

        assert unspt_tab1.optimized_type == OptimizedType.SW_STEERING
        assert unspt_tab2.optimized_type == OptimizedType.SW_STEERING
        assert unspt_tab3.optimized_type == OptimizedType.SW_STEERING
        assert unspt_tab4.optimized_type == OptimizedType.SW_STEERING
        assert unspt_tab5.optimized_type == OptimizedType.SW_STEERING

        assert semispttab1.optimized_type == OptimizedType.SW_STEERING
        assert semispttab2.optimized_type == OptimizedType.SEMI_SUPPORTED
        assert semispttab3.optimized_type == OptimizedType.SEMI_SUPPORTED

        assert spt_tab.optimized_type == OptimizedType.HW_STEERING

    def test_mark_semisupported_unsupported(self, json_path):
        """mark_semisupported_nodes,
        then mark_unsupported_nodes first
        """
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)

        JsonPlanner.mark_semisupported_nodes(irg)
        JsonPlanner.mark_unsupported_nodes(irg)

        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        unspt_tab1 = tables[0]
        unspt_tab2 = tables[1]
        unspt_tab3 = tables[2]
        unspt_tab4 = tables[3]
        unspt_tab5 = tables[4]
        semispttab1 = tables[5]
        semispttab2 = tables[6]
        semispttab3 = tables[7]
        spt_tab = tables[8]

        # TODO: SEMI marks are changed by mark_unsupported_nodes
        # assert unspt_tab1.optimized_type == OptimizedType.SW_STEERING
        # assert unspt_tab2.optimized_type == OptimizedType.SW_STEERING
        # assert unspt_tab3.optimized_type == OptimizedType.SW_STEERING
        # assert unspt_tab4.optimized_type == OptimizedType.SW_STEERING
        # assert unspt_tab5.optimized_type == OptimizedType.SW_STEERING

        # assert semispttab1.optimized_type == OptimizedType.SW_STEERING
        # assert semispttab2.optimized_type == OptimizedType.SEMI_SUPPORTED
        # assert semispttab3.optimized_type == OptimizedType.SEMI_SUPPORTED

        # assert spt_tab.optimized_type == OptimizedType.HW_STEERING
