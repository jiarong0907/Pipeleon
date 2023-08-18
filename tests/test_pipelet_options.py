from copy import deepcopy
from typing import List
import pytest
import os, sys, random, math
import mock_import
from runtime_CLI import RuntimeAPI
from unittest.mock import Mock, patch

from graph_optimizer.algorithms import PipeletOptimizer
from graph_optimizer.options import *
from graph_optimizer.json_manager import JsonManager, JsonPlanner
from graph_optimizer.graph_optimizer import Optimizer
from ir.match_key import MatchType
from commons.constants import OptimizeMethod
from targets.smart_nic import HwSteering, SmartNic
import utils


class TestDeepCopy:
    def test_deepcopy(self):
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        pipelet_tables = pipelet.tables
        utils.set_table_current_sizes(pipelet_tables, [1, 1, 1])

        pipelet_copy = deepcopy(pipelet)
        copy_tables = pipelet_copy.tables

        assert len(pipelet_tables) == len(copy_tables), f"The copied pipelet should have the same number of tables"

        for i in range(len(pipelet_tables)):
            assert pipelet_tables[i].current_size == copy_tables[i].current_size

        # we change the copied pipelet, the original one should be affected
        original_table_sizes = [t.current_size for t in pipelet_tables]
        copy_tables[0].current_size = 2
        copy_tables[1].current_size = 3
        copy_tables[2].current_size = 4
        assert original_table_sizes == [t.current_size for t in pipelet_tables]

    def test_deepcopy_eval(self):
        json_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "softcopy", "test.p4.json")
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        optimizer = Optimizer(api=RuntimeAPI(), sampling_period_us=10000)
        ingress_graph = irg.get_pipe("ingress")
        pipelets = JsonPlanner.get_pipelets(ingress_graph)
        assert len(pipelets) == 1 and len(pipelets[0].tables) == 4
        original_pipelet = pipelets[0]
        pipelet_copy = deepcopy(original_pipelet)
        # re-split the original pipelet before we evaluate it
        optimizer._update_pipeline_stats(irg, utils.gen_runtime_stats(pipelet_copy.tables, []))
        JsonPlanner._resplit_irg_pipe(original_pipelet.irgraph_pipe)
        original_eval_metric = original_pipelet.irgraph_pipe.eval()
        JsonPlanner.apply_reordering(pipelet_copy, ReorderOption([3, 2, 1, 0]))


@patch("graph_optimizer.plan_evaluator.PlanEvaluator._eval_pipelet_option")
class TestReoptimizePipelet:
    def test_no_optimization(self, mock_gain_cost):
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0, 0])
        utils.set_table_current_sizes(tables, [1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1])
        pipelet.irgraph_pipe.target = SmartNic()
        optimize_method = []
        pipelet_options = PipeletOptimizer._compute_all_options(pipelet, optimize_method)
        mock_gain_cost.assert_not_called()
        assert len(pipelet_options) == 0
        for po in pipelet_options:
            assert po.combined_options == None

    def test_only_reorder(self, mock_gain_cost):
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0, 0])
        utils.set_table_current_sizes(tables, [1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1])
        pipelet.irgraph_pipe.target = SmartNic()
        optimize_method = [OptimizeMethod.REORDER]
        pipelet_options = PipeletOptimizer._compute_all_options(pipelet, optimize_method)
        mock_gain_cost.assert_called()
        assert len(pipelet_options) == math.factorial(3) - 1
        for po in pipelet_options:
            assert po.combined_options == None

    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "reorder_entry_insert", "insert_end.p4.json"
            )
        ],
    )
    def test_only_reorder_insert_entry_end(self, mock_gain_cost, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)
        assert len(pipelets) == 1

        utils.set_table_optimized_types(tables, [0, 0, 0])
        utils.set_table_current_sizes(tables, [1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1])
        # pipelet.irgraph_pipe.target = SmartNic()
        optimize_method = [OptimizeMethod.REORDER]
        pipelet_options = PipeletOptimizer._compute_all_options(pipelets[0], optimize_method)
        mock_gain_cost.assert_called()
        assert len(pipelet_options) == 1
        assert pipelet_options[0].new_order.new_table_pos == [1, 0, 2]

    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "reorder_entry_insert", "insert_mid.p4.json"
            )
        ],
    )
    def test_only_reorder_insert_entry_mid(self, mock_gain_cost, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        pipelets = JsonPlanner.get_pipelets(ingress_graph)
        assert len(pipelets) == 1

        utils.set_table_optimized_types(tables, [0, 0, 0])
        utils.set_table_current_sizes(tables, [1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1])
        # pipelet.irgraph_pipe.target = SmartNic()
        optimize_method = [OptimizeMethod.REORDER]
        pipelet_options = PipeletOptimizer._compute_all_options(pipelets[0], optimize_method)
        # mock_gain_cost.assert_called()
        assert len(pipelet_options) == 0
        # assert pipelet_options[0].new_order.new_table_pos == [0,1,2]

    def test_only_softcopy(self, mock_gain_cost):
        mock_gain_cost.return_value = None
        pipelet = utils.create_pipelet(6, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [2, 0, 2, 0, 0, 1])
        utils.set_table_current_sizes(tables, [1, 1, 1, 1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1, 1, 1, 1])
        pipelet.irgraph_pipe.target = SmartNic()
        optimize_method = [OptimizeMethod.SOFTCOPY]
        pipelet_options = PipeletOptimizer._compute_all_options(pipelet, optimize_method)
        mock_gain_cost.assert_called()
        assert len(pipelet_options) == 3
        for po in pipelet_options:
            assert po.combined_options != None
            assert len(po.combined_options) == 1 or len(po.combined_options) == 2
            if len(po.combined_options) == 2:
                assert po.combined_options[0].start_table_id == 1
                assert po.combined_options[1].start_table_id == 3
                assert po.combined_options[0].length == 1
                assert po.combined_options[1].length == 2
            else:
                assert po.combined_options[0].start_table_id in [1, 3]
                if po.combined_options[0].start_table_id == 1:
                    assert po.combined_options[0].length == 1
                else:
                    assert po.combined_options[0].length == 2

    def test_only_softmove(self, mock_gain_cost):
        mock_gain_cost.return_value = None
        pipelet = utils.create_pipelet(6, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 0, 1, 0, 0, 1])
        utils.set_table_current_sizes(tables, [1, 1, 1, 1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1, 1, 1, 1])
        pipelet.irgraph_pipe.target = SmartNic()
        optimize_method = [OptimizeMethod.SOFTMOVE]
        pipelet_options = PipeletOptimizer._compute_all_options(pipelet, optimize_method)
        mock_gain_cost.assert_called()
        assert len(pipelet_options) == 3
        for po in pipelet_options:
            assert po.combined_options != None
            assert len(po.combined_options) == 1 or len(po.combined_options) == 2
            if len(po.combined_options) == 2:
                assert po.combined_options[0].start_table_id == 1
                assert po.combined_options[1].start_table_id == 3
                assert po.combined_options[0].length == 1
                assert po.combined_options[1].length == 2
            else:
                assert po.combined_options[0].start_table_id in [1, 3]
                if po.combined_options[0].start_table_id == 1:
                    assert po.combined_options[0].length == 1
                else:
                    assert po.combined_options[0].length == 2

    def test_only_merge(self, mock_gain_cost):
        mock_gain_cost.return_value = None
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 0, 0, 0, 1])
        utils.set_table_current_sizes(tables, [1, 1, 1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1, 1, 1])
        pipelet.irgraph_pipe.target = SmartNic()
        optimize_method = [OptimizeMethod.MERGE]
        pipelet_options = PipeletOptimizer._compute_all_options(pipelet, optimize_method)
        mock_gain_cost.assert_called()
        assert len(pipelet_options) == 2
        for po in pipelet_options:
            assert po.combined_options != None
            assert len(po.combined_options) == 1
            assert po.combined_options[0].start_table_id in [1, 2]
            assert po.combined_options[0].length == 2

    def test_only_cache(self, mock_gain_cost):
        mock_gain_cost.return_value = None
        pipelet = utils.create_pipelet(6, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 0, 0, 1, 0, 1])
        utils.set_table_current_sizes(tables, [1, 1, 1, 1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1, 1, 1, 1])
        pipelet.irgraph_pipe.target = SmartNic()
        optimize_method = [OptimizeMethod.CACHE]
        pipelet_options = PipeletOptimizer._compute_all_options(pipelet, optimize_method)
        mock_gain_cost.assert_called()
        assert len(pipelet_options) == 4
        for po in pipelet_options:
            assert po.combined_options != None
            assert len(po.combined_options) == 1
            if po.combined_options[0].length == 2:
                assert po.combined_options[0].start_table_id == 1
            else:
                assert po.combined_options[0].start_table_id in [1, 2, 4]

    def test_reorder_softcopy(self, mock_gain_cost):
        mock_gain_cost.return_value = None
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 2, 0])
        utils.set_table_current_sizes(tables, [1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1])
        pipelet.irgraph_pipe.target = SmartNic()
        optimize_method = [OptimizeMethod.REORDER, OptimizeMethod.SOFTCOPY]
        pipelet_options = PipeletOptimizer._compute_all_options(pipelet, optimize_method)
        mock_gain_cost.assert_called()
        assert len(pipelet_options) == 9

    def test_reorder_softmove(self, mock_gain_cost):
        mock_gain_cost.return_value = None
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 1, 0])
        utils.set_table_current_sizes(tables, [1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1])
        pipelet.irgraph_pipe.target = SmartNic()
        optimize_method = [OptimizeMethod.REORDER, OptimizeMethod.SOFTMOVE]
        pipelet_options = PipeletOptimizer._compute_all_options(pipelet, optimize_method)
        mock_gain_cost.assert_called()
        assert len(pipelet_options) == 15

    def test_reorder_merge(self, mock_gain_cost):
        mock_gain_cost.return_value = None
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 1, 0])
        utils.set_table_current_sizes(tables, [1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1])
        pipelet.irgraph_pipe.target = SmartNic()
        optimize_method = [OptimizeMethod.REORDER, OptimizeMethod.MERGE]
        pipelet_options = PipeletOptimizer._compute_all_options(pipelet, optimize_method)
        mock_gain_cost.assert_called()
        assert len(pipelet_options) == 9
        merge_plan_num = 0
        for po in pipelet_options:
            if po.combined_options != None:
                merge_plan_num += 1
        assert merge_plan_num == 4

    def test_reorder_cache(self, mock_gain_cost):
        mock_gain_cost.return_value = None
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 1, 0])
        utils.set_table_current_sizes(tables, [1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1])
        pipelet.irgraph_pipe.target = SmartNic()
        optimize_method = [OptimizeMethod.REORDER, OptimizeMethod.CACHE]
        pipelet_options = PipeletOptimizer._compute_all_options(pipelet, optimize_method)
        mock_gain_cost.assert_called()
        assert len(pipelet_options) == 21

    def test_all_optimizations1(self, mock_gain_cost):
        mock_gain_cost.return_value = None
        pipelet = utils.create_pipelet(1, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0])
        utils.set_table_current_sizes(tables, [1])
        utils.set_table_insertion_rates(tables, [1])
        pipelet.irgraph_pipe.target = SmartNic()
        optimize_method = [
            OptimizeMethod.REORDER,
            OptimizeMethod.SOFTCOPY,
            OptimizeMethod.MERGE,
            OptimizeMethod.CACHE,
            OptimizeMethod.SOFTMOVE,
        ]
        pipelet_options = PipeletOptimizer._compute_all_options(pipelet, optimize_method)
        mock_gain_cost.assert_called()
        assert len(pipelet_options) == 1

    def test_all_optimizations2(self, mock_gain_cost):
        mock_gain_cost.return_value = None
        pipelet = utils.create_pipelet(2, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0])
        utils.set_table_current_sizes(tables, [1, 1])
        utils.set_table_insertion_rates(tables, [1, 1])
        pipelet.irgraph_pipe.target = SmartNic()
        optimize_method = [
            OptimizeMethod.REORDER,
            OptimizeMethod.SOFTCOPY,
            OptimizeMethod.MERGE,
            OptimizeMethod.CACHE,
            OptimizeMethod.SOFTMOVE,
        ]
        pipelet_options = PipeletOptimizer._compute_all_options(pipelet, optimize_method)
        mock_gain_cost.assert_called()
        assert len(pipelet_options) == 11

    def test_all_optimizations3(self, mock_gain_cost):
        mock_gain_cost.return_value = None
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 1, 0])
        utils.set_table_current_sizes(tables, [1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1])
        pipelet.irgraph_pipe.target = SmartNic()
        optimize_method = [
            OptimizeMethod.REORDER,
            OptimizeMethod.SOFTCOPY,
            OptimizeMethod.MERGE,
            OptimizeMethod.CACHE,
            OptimizeMethod.SOFTMOVE,
        ]
        pipelet_options = PipeletOptimizer._compute_all_options(pipelet, optimize_method)
        mock_gain_cost.assert_called()
        assert len(pipelet_options) == 39


class TestValidateCombinedOpts:
    def test_invalid_two_overlapping_caches(self):
        pipelet = utils.create_pipelet(4, MatchType.TERNARY)
        opt1 = CacheOption(0, 1)
        opt2 = CacheOption(0, 2)
        is_valid = PipeletOptimizer._validate_combined_opts(pipelet, [opt1, opt2])
        assert is_valid == False

    def test_invalid_two_nonoverlapping_caches(self):
        pipelet = utils.create_pipelet(4, MatchType.TERNARY)
        opt1 = CacheOption(0, 1)
        opt2 = CacheOption(1, 2)
        is_valid = PipeletOptimizer._validate_combined_opts(pipelet, [opt1, opt2])
        assert is_valid == False

    def test_invalid_two_overlapping_merge(self):
        pipelet = utils.create_pipelet(4, MatchType.TERNARY)
        opt1 = MergeOption(0, 2)
        opt2 = MergeOption(1, 2)
        is_valid = PipeletOptimizer._validate_combined_opts(pipelet, [opt1, opt2])
        assert is_valid == False

    def test_invalid_two_overlapping_softcopy(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        opt1 = SoftcopyOption(0, 3)
        opt2 = SoftcopyOption(1, 1)
        is_valid = PipeletOptimizer._validate_combined_opts(pipelet, [opt1, opt2])
        assert is_valid == False

    def test_invalid_two_overlapping_softmove(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        opt1 = SoftmoveOption(0, 3)
        opt2 = SoftmoveOption(1, 1)
        is_valid = PipeletOptimizer._validate_combined_opts(pipelet, [opt1, opt2])
        assert is_valid == False

    def test_invalid_overlapping_merge_softcopy(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        opt1 = MergeOption(0, 3)
        opt2 = SoftcopyOption(1, 1)
        is_valid = PipeletOptimizer._validate_combined_opts(pipelet, [opt1, opt2])
        assert is_valid == False

    def test_invalid_overlapping_merge_softmove(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        opt1 = MergeOption(0, 3)
        opt2 = SoftmoveOption(1, 1)
        is_valid = PipeletOptimizer._validate_combined_opts(pipelet, [opt1, opt2])
        assert is_valid == False

    def test_invalid_overlapping_merge_cache(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        opt1 = MergeOption(0, 2)
        opt2 = CacheOption(0, 5)
        is_valid = PipeletOptimizer._validate_combined_opts(pipelet, [opt1, opt2])
        assert is_valid == False

    def test_invalid_overlapping_softcopy_cache(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        opt1 = SoftcopyOption(0, 2)
        opt2 = CacheOption(1, 3)
        is_valid = PipeletOptimizer._validate_combined_opts(pipelet, [opt1, opt2])
        assert is_valid == False

    def test_invalid_overlapping_multi_options1(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        opt1 = SoftcopyOption(4, 1)
        opt2 = CacheOption(1, 3)
        opt3 = MergeOption(0, 2)
        is_valid = PipeletOptimizer._validate_combined_opts(pipelet, [opt1, opt2, opt3])
        assert is_valid == False

    def test_invalid_overlapping_multi_options2(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        opt1 = SoftcopyOption(4, 1)
        opt2 = CacheOption(0, 5)
        opt3 = MergeOption(0, 2)
        is_valid = PipeletOptimizer._validate_combined_opts(pipelet, [opt1, opt2, opt3])
        assert is_valid == False

    def test_valid_two_nonoverlapping_merge(self):
        pipelet = utils.create_pipelet(4, MatchType.TERNARY)
        opt1 = MergeOption(0, 2)
        opt2 = MergeOption(2, 2)
        is_valid = PipeletOptimizer._validate_combined_opts(pipelet, [opt1, opt2])
        assert is_valid == True

    def test_valid_two_nonoverlapping_softcopy(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        opt1 = SoftcopyOption(0, 2)
        opt2 = SoftcopyOption(2, 1)
        is_valid = PipeletOptimizer._validate_combined_opts(pipelet, [opt1, opt2])
        assert is_valid == True

    def test_valid_nonoverlapping_merge_softcopy(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        opt1 = MergeOption(0, 2)
        opt2 = SoftcopyOption(2, 2)
        is_valid = PipeletOptimizer._validate_combined_opts(pipelet, [opt1, opt2])
        assert is_valid == True

    def test_valid_overlapping_merge_cache(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        opt1 = MergeOption(0, 2)
        opt2 = CacheOption(2, 3)
        is_valid = PipeletOptimizer._validate_combined_opts(pipelet, [opt1, opt2])
        assert is_valid == True

    def test_valid_overlapping_softcopy_cache(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        opt1 = SoftcopyOption(0, 2)
        opt2 = CacheOption(2, 3)
        is_valid = PipeletOptimizer._validate_combined_opts(pipelet, [opt1, opt2])
        assert is_valid == True

    def test_valid_overlapping_multi_options1(self):
        pipelet = utils.create_pipelet(8, MatchType.TERNARY)
        opt1 = SoftcopyOption(4, 1)
        opt2 = CacheOption(5, 3)
        opt3 = MergeOption(0, 2)
        is_valid = PipeletOptimizer._validate_combined_opts(pipelet, [opt1, opt2, opt3])
        assert is_valid == True

    def test_random_options(self):
        for _ in range(100):
            pipelet_length = 10
            pipelet = utils.create_pipelet(pipelet_length, MatchType.TERNARY)
            start1 = random.randint(0, pipelet_length - 1)
            start2 = random.randint(0, pipelet_length - 1)
            start3 = random.randint(0, pipelet_length - 2 - 1)
            start4 = random.randint(0, pipelet_length - 1)
            size1 = random.randint(0, pipelet_length - start1 - 1)
            size2 = random.randint(0, pipelet_length - start2 - 1)
            size3 = random.randint(0, pipelet_length - start4 - 1)

            expected = (
                len(
                    list(
                        set(range(start1, start1 + size1))
                        | set(range(start2, start2 + size2))
                        | set(range(start4, start4 + size3))
                        | set(range(start3, start3 + 2))
                    )
                )
                == size1 + size2 + size3 + 2
            )

            opt1 = SoftcopyOption(start1, size1)
            opt2 = CacheOption(start2, size2)
            opt3 = MergeOption(start3, 2)
            opt4 = MergeOption(start4, size3)
            is_valid = PipeletOptimizer._validate_combined_opts(pipelet, [opt1, opt2, opt3, opt4])
            assert is_valid == expected
