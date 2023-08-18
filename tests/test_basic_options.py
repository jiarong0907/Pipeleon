from typing import List
import pytest
import os, sys, random, math
import mock_import

from graph_optimizer.algorithms import PipeletOptimizer
from graph_optimizer.json_manager import JsonManager, JsonPlanner
from ir.match_key import MatchType
from ir.table import Table
import utils


class TestReorder:
    def test_option_num(self):
        """
        Test that the algorithm can generate the right number of plans
        """
        for _ in range(100):
            table_num = random.randint(1, 6)
            pipelet = utils.create_pipelet(table_num, MatchType.TERNARY)
            plans = PipeletOptimizer._compute_reorder_plan(pipelet)
            assert len(plans) == math.factorial(table_num)
        pipelet = utils.create_pipelet(1, MatchType.TERNARY)
        plans = PipeletOptimizer._compute_reorder_plan(pipelet)
        assert len(plans) == 1

    def test_option_content(self):
        """
        Test that the algorithm can generate the right plans
        """
        pipelet = utils.create_pipelet(1, MatchType.TERNARY)
        plans = PipeletOptimizer._compute_reorder_plan(pipelet)
        assert plans[0].new_table_pos == [0]

        pipelet = utils.create_pipelet(2, MatchType.TERNARY)
        plans = PipeletOptimizer._compute_reorder_plan(pipelet)
        assert plans[0].new_table_pos in [[0, 1], [1, 0]] and plans[1].new_table_pos in [[0, 1], [1, 0]]


class TestSoftcopy:
    def test_single_option_single_table_middle(self):
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [2, 0, 1])
        plans = PipeletOptimizer._compute_softcopy_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 1 and plans[0].length == 1

    def test_single_option_single_table_front(self):
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 1, 1])
        plans = PipeletOptimizer._compute_softcopy_plan(pipelet)
        assert len(plans) == 0

    def test_single_option_single_table_end(self):
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 2, 0])
        plans = PipeletOptimizer._compute_softcopy_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 2 and plans[0].length == 1

    def test_single_option_multi_table_middle(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [2, 0, 0, 0, 1])
        plans = PipeletOptimizer._compute_softcopy_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 1 and plans[0].length == 3

    def test_single_option_multi_table_front(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0, 0, 1, 1])
        plans = PipeletOptimizer._compute_softcopy_plan(pipelet)
        assert len(plans) == 0

    def test_single_option_multi_table_end(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 2, 0, 0, 0])
        plans = PipeletOptimizer._compute_softcopy_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 2 and plans[0].length == 3

    def test_multi_option_single_table_middle(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [2, 0, 2, 0, 1])
        plans = PipeletOptimizer._compute_softcopy_plan(pipelet)
        assert len(plans) == 2
        assert plans[0].start_table_id == 1 and plans[0].length == 1
        assert plans[1].start_table_id == 3 and plans[1].length == 1

    def test_multi_option_single_table_front(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 2, 0, 1, 1])
        plans = PipeletOptimizer._compute_softcopy_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 2 and plans[0].length == 1

    def test_multi_option_single_table_end(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 1, 1, 2, 0])
        plans = PipeletOptimizer._compute_softcopy_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 4 and plans[0].length == 1

    def test_multi_option_multi_table(self):
        pipelet = utils.create_pipelet(7, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 2, 0, 0, 2, 2, 0])
        plans = PipeletOptimizer._compute_softcopy_plan(pipelet)
        assert len(plans) == 2
        assert plans[0].start_table_id == 2 and plans[0].length == 2
        assert plans[1].start_table_id == 6 and plans[1].length == 1

    def test_no_option(self):
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 1, 2])
        plans = PipeletOptimizer._compute_softcopy_plan(pipelet)
        assert len(plans) == 0


class TestSoftmove:
    def test_single_option_single_table_middle(self):
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 0, 1])
        plans = PipeletOptimizer._compute_softmove_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 1 and plans[0].length == 1

    def test_single_option_single_table_front(self):
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 1, 1])
        plans = PipeletOptimizer._compute_softmove_plan(pipelet)
        assert len(plans) == 1

    def test_single_option_single_table_end(self):
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 1, 0])
        plans = PipeletOptimizer._compute_softmove_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 2 and plans[0].length == 1

    def test_single_option_multi_table_middle(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 0, 0, 0, 1])
        plans = PipeletOptimizer._compute_softmove_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 1 and plans[0].length == 3

    def test_single_option_multi_table_front(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0, 0, 1, 1])
        plans = PipeletOptimizer._compute_softmove_plan(pipelet)
        assert len(plans) == 1

    def test_single_option_multi_table_end(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 1, 0, 0, 0])
        plans = PipeletOptimizer._compute_softmove_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 2 and plans[0].length == 3

    def test_multi_option_single_table_middle(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 0, 1, 0, 1])
        plans = PipeletOptimizer._compute_softmove_plan(pipelet)
        assert len(plans) == 2
        assert plans[0].start_table_id == 1 and plans[0].length == 1
        assert plans[1].start_table_id == 3 and plans[1].length == 1

    def test_multi_option_single_table_front(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 1, 0, 1, 1])
        plans = PipeletOptimizer._compute_softmove_plan(pipelet)
        assert len(plans) == 2
        assert plans[0].start_table_id == 0 and plans[0].length == 1
        assert plans[1].start_table_id == 2 and plans[1].length == 1

    def test_multi_option_single_table_end(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 1, 1, 1, 0])
        plans = PipeletOptimizer._compute_softmove_plan(pipelet)
        assert len(plans) == 2
        assert plans[0].start_table_id == 0 and plans[0].length == 1
        assert plans[1].start_table_id == 4 and plans[1].length == 1

    def test_multi_option_multi_table(self):
        pipelet = utils.create_pipelet(7, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 2, 0, 0, 2, 2, 0])
        plans = PipeletOptimizer._compute_softmove_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 0 and plans[0].length == 1

    def test_no_option(self):
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 1, 2])
        plans = PipeletOptimizer._compute_softmove_plan(pipelet)
        assert len(plans) == 0


class TestMerge:
    def test_no_option_all_software(self):
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 1, 2])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 0

    def test_no_option_no_consecutive_table1(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 0, 1, 0, 1])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 0

    def test_no_option_no_consecutive_table2(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 1, 0, 1, 0])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 0

    def test_no_option_large_table1(self):
        pipelet = utils.create_pipelet(4, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0, 0, 1])
        utils.set_table_current_sizes(tables, [150, 10, 101, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1, 1])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 0

    def test_no_option_large_table2(self):
        pipelet = utils.create_pipelet(4, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0, 0, 1])
        utils.set_table_current_sizes(tables, [10, 200, 10, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1, 1])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 0

    def test_no_option_large_table3(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0, 0, 1, 0])
        utils.set_table_current_sizes(tables, [10, 200, 10, 10, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1, 1, 1])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 0

    def test_no_option_high_insertion_rate1(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0, 0, 0, 0])
        utils.set_table_current_sizes(tables, [10, 10, 10, 10, 10])
        utils.set_table_insertion_rates(tables, [10, 20, 10, 20, 1])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 0

    def test_no_option_high_insertion_rate2(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0, 0, 0, 0])
        utils.set_table_current_sizes(tables, [10, 10, 10, 10, 10])
        utils.set_table_insertion_rates(tables, [20, 10, 15, 20, 1])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 0

    def test_no_option_high_insertion_rate3(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0, 1, 0, 0])
        utils.set_table_current_sizes(tables, [10, 10, 10, 10, 10])
        utils.set_table_insertion_rates(tables, [20, 1, 1, 20, 1])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 0

    def test_no_option_not_on_hardware(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 2, 2, 1, 1])
        utils.set_table_current_sizes(tables, [1, 1, 1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1, 1, 1])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 0

    def test_single_option_front1(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0, 2, 1, 1])
        utils.set_table_current_sizes(tables, [1, 1, 1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1, 1, 1])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 0 and plans[0].length == 2

    def test_single_option_front2(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0, 0, 0, 0])
        utils.set_table_current_sizes(tables, [1, 1, 1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 100, 100, 1])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 0 and plans[0].length == 2

    def test_single_option_middle1(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 1, 0, 0, 1])
        utils.set_table_current_sizes(tables, [1, 1, 1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1, 1, 1])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 2 and plans[0].length == 2

    def test_single_option_middle2(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0, 0, 0, 0])
        utils.set_table_current_sizes(tables, [1, 150, 1, 1, 150])
        utils.set_table_insertion_rates(tables, [1, 1, 1, 1, 1])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 2 and plans[0].length == 2

    def test_single_option_end1(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 1, 1, 0, 0])
        utils.set_table_current_sizes(tables, [1, 1, 1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1, 1, 1])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 3 and plans[0].length == 2

    def test_single_option_end2(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0, 0, 0, 0])
        utils.set_table_current_sizes(tables, [1, 1, 150, 1, 1])
        utils.set_table_insertion_rates(tables, [100, 1, 1, 1, 1])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 3 and plans[0].length == 2

    def test_multi_option_nonoverlapping1(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0, 1, 0, 0])
        utils.set_table_current_sizes(tables, [1, 1, 1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1, 1, 1])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 2
        assert plans[0].start_table_id == 0 and plans[0].length == 2
        assert plans[1].start_table_id == 3 and plans[0].length == 2

    def test_multi_option_nonoverlapping2(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0, 0, 0, 0])
        utils.set_table_current_sizes(tables, [1, 1, 1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 12, 1, 1])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 2
        assert plans[0].start_table_id == 0 and plans[0].length == 2
        assert plans[1].start_table_id == 3 and plans[0].length == 2

    def test_multi_option_overlapping1(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 0, 0, 0, 1])
        utils.set_table_current_sizes(tables, [1, 1, 1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1, 1, 1])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 2
        assert plans[0].start_table_id == 1 and plans[0].length == 2
        assert plans[1].start_table_id == 2 and plans[0].length == 2

    def test_multi_option_overlapping2(self):
        pipelet = utils.create_pipelet(5, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0, 0, 0, 0])
        utils.set_table_current_sizes(tables, [1, 1, 1, 1, 1])
        utils.set_table_insertion_rates(tables, [1, 1, 1, 1, 1])
        plans = PipeletOptimizer._compute_table_merge_plan(pipelet)
        assert len(plans) == 4
        assert plans[0].start_table_id == 0 and plans[0].length == 2
        assert plans[1].start_table_id == 1 and plans[0].length == 2
        assert plans[2].start_table_id == 2 and plans[0].length == 2
        assert plans[3].start_table_id == 3 and plans[0].length == 2

    @pytest.mark.parametrize(
        "json_path", [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "merge", "test.p4.json")]
    )
    def test_merge_with_dependency(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        pipelets = JsonPlanner.get_pipelets(ingress_graph)
        tables = list(ingress_graph.tables)
        utils.set_table_optimized_types(tables, [0] * len(tables))
        utils.set_table_current_sizes(tables, [1] * len(tables))
        utils.set_table_insertion_rates(tables, [1] * len(tables))
        plans = PipeletOptimizer._compute_table_merge_plan(pipelets[0])
        assert len(plans) == 4


class TestCache:
    def test_no_option_all_software(self):
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 1, 2])
        plans = PipeletOptimizer._compute_cache_plan(pipelet)
        assert len(plans) == 0

    def test_single_option_front(self):
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 1, 1])
        plans = PipeletOptimizer._compute_cache_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 0 and plans[0].length == 1

    def test_single_option_front_exact(self):
        pipelet = utils.create_pipelet(3, MatchType.EXACT)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 1, 1])
        plans = PipeletOptimizer._compute_cache_plan(pipelet)
        assert len(plans) == 0

    def test_single_option_middle(self):
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 0, 1])
        plans = PipeletOptimizer._compute_cache_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 1 and plans[0].length == 1

    def test_single_option_end(self):
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [1, 1, 0])
        plans = PipeletOptimizer._compute_cache_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 2 and plans[0].length == 1

    def test_multi_option_consecutive(self):
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0, 0])
        plans = PipeletOptimizer._compute_cache_plan(pipelet)
        assert len(plans) == 6
        assert plans[0].start_table_id == 0 and plans[0].length == 1
        assert plans[1].start_table_id == 0 and plans[1].length == 2
        assert plans[2].start_table_id == 0 and plans[2].length == 3
        assert plans[3].start_table_id == 1 and plans[3].length == 1
        assert plans[4].start_table_id == 1 and plans[4].length == 2
        assert plans[5].start_table_id == 2 and plans[5].length == 1

    def test_multi_option_consecutive_exact(self):
        pipelet = utils.create_pipelet(3, MatchType.EXACT)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 0, 0])
        plans = PipeletOptimizer._compute_cache_plan(pipelet)
        assert len(plans) == 3
        assert plans[0].start_table_id == 0 and plans[0].length == 2
        assert plans[1].start_table_id == 0 and plans[1].length == 3
        assert plans[2].start_table_id == 1 and plans[2].length == 2

    def test_multi_option_nonconsecutive1(self):
        pipelet = utils.create_pipelet(3, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 1, 0])
        plans = PipeletOptimizer._compute_cache_plan(pipelet)
        assert len(plans) == 2
        assert plans[0].start_table_id == 0 and plans[0].length == 1
        assert plans[1].start_table_id == 2 and plans[1].length == 1

    def test_multi_option_nonconsecutive2(self):
        pipelet = utils.create_pipelet(4, MatchType.TERNARY)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 1, 0, 0])
        plans = PipeletOptimizer._compute_cache_plan(pipelet)
        assert len(plans) == 4
        assert plans[0].start_table_id == 0 and plans[0].length == 1
        assert plans[1].start_table_id == 2 and plans[1].length == 1
        assert plans[2].start_table_id == 2 and plans[2].length == 2
        assert plans[3].start_table_id == 3 and plans[3].length == 1

    def test_multi_option_nonconsecutive2_exact(self):
        pipelet = utils.create_pipelet(4, MatchType.EXACT)
        tables = pipelet.tables
        utils.set_table_optimized_types(tables, [0, 1, 0, 0])
        plans = PipeletOptimizer._compute_cache_plan(pipelet)
        assert len(plans) == 1
        assert plans[0].start_table_id == 2 and plans[0].length == 2
