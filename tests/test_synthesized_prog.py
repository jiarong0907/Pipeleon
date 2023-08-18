import pytest
import os, sys
import mock_import
from unittest.mock import patch

from graph_optimizer.json_manager import JsonManager
from commons.constants import OptimizeMethod, OptimizeTarget
import utils


@pytest.mark.parametrize(
    "json_path",
    [
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "synthesized", f"prog_{i}.p4.json")
        for i in range(51)
    ],
)
class TestSynthesizedProgJsonLoad:
    def test_json_load(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        print(f"number of tables {len(tables)}")


class TestSynthesizedProgReorder:
    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "synthesized", f"prog_{i}.p4.json")
            for i in range(1, 2)
        ],
    )
    @patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
    def test_reorder(self, retrieve_runtime_states, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        conds = list(ingress_graph.conditions)
        retrieve_runtime_states.return_value = utils.gen_runtime_stats(tables, conds)

        pipelet_options = utils._call_optimizer(irg, [OptimizeMethod.REORDER], OptimizeTarget.LATENCY)
