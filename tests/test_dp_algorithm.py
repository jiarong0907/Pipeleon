from typing import List, Tuple
import pytest
import os, sys, random
import mock_import
from runtime_CLI import RuntimeAPI
from unittest.mock import patch
from collections import OrderedDict

from graph_optimizer.algorithms import PipeletOptimizer
from graph_optimizer.graph_optimizer import Optimizer
from graph_optimizer.options import *
from graph_optimizer.json_manager import JsonManager, JsonPlanner
import commons.config as config
from commons.constants import TOTAL_ENTRY_INSERTION, TOTAL_MEMORY, OptimizeMethod, OptimizeTarget
from graph_optimizer.runtime_states import ActionMeta, TableCountProfile, RuntimeStates
from ir.table import Table
from ir.irgraph import IrGraph
from ir.match_key import MatchType
from commons.types import LatencyPdf
from targets.smart_nic import latencies_list_add_item
import utils


@patch("graph_optimizer.plan_evaluator.PlanEvaluator._eval_pipelet_option")
class TestDpAlgorithm:
    def test_single_pipelet_within_resources(self, mock_gain_cost):
        for _ in range(50):
            pipelet = utils.create_pipelet_asic_static_small(3, MatchType.TERNARY)
            optimize_method = [
                OptimizeMethod.REORDER,
                OptimizeMethod.SOFTCOPY,
                OptimizeMethod.MERGE,
                OptimizeMethod.CACHE,
                OptimizeMethod.SOFTMOVE,
            ]
            pipelet_options = PipeletOptimizer._compute_all_options(pipelet, optimize_method)
            mock_gain_cost.assert_called()
            assert len(pipelet_options) == 71
            max_gain = -1
            best_option = []
            mavail, iavail = TOTAL_MEMORY, TOTAL_ENTRY_INSERTION
            for i in range(len(pipelet_options)):
                lgain = random.randint(1, 100)
                if lgain > max_gain:
                    max_gain = lgain
                    best_option = [pipelet_options[i]]
                elif lgain == max_gain:
                    best_option.append(pipelet_options[i])
                utils.set_pipelet_option_gain_cost(
                    pipelet_options[i],
                    mcost=random.randint(1, mavail - config.DP_MSTEP - 1),
                    icost=random.randint(1, iavail - config.DP_ISTEP - 1),
                    lgain=lgain,
                    tgain=1,
                )

            res = PipeletOptimizer._compute_best_global_plan_dp(
                mavail, iavail, OptimizeTarget.LATENCY, [pipelet_options]
            )
            assert res != None and len(res.option) == 1
            assert res.option[0] in best_option

    def test_single_pipelet_partial_within_resources(self, mock_gain_cost):
        for _ in range(50):
            pipelet = utils.create_pipelet_asic_static_small(3, MatchType.TERNARY)
            optimize_method = [
                OptimizeMethod.REORDER,
                OptimizeMethod.SOFTCOPY,
                OptimizeMethod.MERGE,
                OptimizeMethod.CACHE,
                OptimizeMethod.SOFTMOVE,
            ]
            pipelet_options = PipeletOptimizer._compute_all_options(pipelet, optimize_method)
            mock_gain_cost.assert_called()
            assert len(pipelet_options) == 71
            max_gain = -1
            best_option = []
            mavail, iavail = TOTAL_MEMORY, TOTAL_ENTRY_INSERTION
            for i in range(len(pipelet_options)):
                if random.randint(1, 10) > 5:
                    mcost = random.randint(mavail, mavail * 2)
                    icost = random.randint(iavail, iavail * 2)
                    lgain = random.randint(500, 1000)
                else:
                    mcost = random.randint(1, mavail - config.DP_MSTEP - 1)
                    icost = random.randint(1, iavail - config.DP_ISTEP - 1)
                    lgain = random.randint(1, 500)
                    if lgain > max_gain:
                        max_gain = lgain
                        best_option = [pipelet_options[i]]
                    elif lgain == max_gain:
                        best_option.append(pipelet_options[i])
                utils.set_pipelet_option_gain_cost(pipelet_options[i], mcost=mcost, icost=icost, lgain=lgain, tgain=1)

            res = PipeletOptimizer._compute_best_global_plan_dp(
                mavail, iavail, OptimizeTarget.LATENCY, [pipelet_options]
            )
            assert res != None and len(res.option) == 1
            assert res.option[0] in best_option

    def test_single_pipelet_beyond_resources(self, mock_gain_cost):
        for _ in range(50):
            pipelet = utils.create_pipelet_asic_static_small(3, MatchType.TERNARY)
            optimize_method = [
                OptimizeMethod.REORDER,
                OptimizeMethod.SOFTCOPY,
                OptimizeMethod.MERGE,
                OptimizeMethod.CACHE,
                OptimizeMethod.SOFTMOVE,
            ]
            pipelet_options = PipeletOptimizer._compute_all_options(pipelet, optimize_method)
            mock_gain_cost.assert_called()
            assert len(pipelet_options) == 71
            mavail, iavail = TOTAL_MEMORY, TOTAL_ENTRY_INSERTION
            for i in range(len(pipelet_options)):
                mcost = random.randint(mavail, mavail * 2)
                icost = random.randint(iavail, iavail * 2)
                lgain = random.randint(500, 1000)
                utils.set_pipelet_option_gain_cost(pipelet_options[i], mcost=mcost, icost=icost, lgain=lgain, tgain=1)

            res = PipeletOptimizer._compute_best_global_plan_dp(
                mavail, iavail, OptimizeTarget.LATENCY, [pipelet_options]
            )
            assert res == None

    def test_two_pipelets_within_resources(self, mock_gain_cost):
        for _ in range(50):
            pipelet1 = utils.create_pipelet_asic_static_small(2, MatchType.TERNARY)
            pipelet2 = utils.create_pipelet_asic_static_small(2, MatchType.TERNARY)
            optimize_method = [
                OptimizeMethod.REORDER,
                OptimizeMethod.SOFTCOPY,
                OptimizeMethod.MERGE,
                OptimizeMethod.CACHE,
                OptimizeMethod.SOFTMOVE,
            ]
            pipelet1_options = PipeletOptimizer._compute_all_options(pipelet1, optimize_method)
            pipelet2_options = PipeletOptimizer._compute_all_options(pipelet2, optimize_method)
            mock_gain_cost.assert_called()
            assert len(pipelet1_options) == 11 and len(pipelet2_options) == 11
            mavail, iavail = TOTAL_MEMORY, TOTAL_ENTRY_INSERTION
            max_gain1 = -1
            best_option1 = []
            for i in range(len(pipelet1_options)):
                lgain = random.randint(1, 100)
                if lgain > max_gain1:
                    max_gain1 = lgain
                    best_option1 = [pipelet1_options[i]]
                elif lgain == max_gain1:
                    best_option1.append(pipelet1_options[i])
                utils.set_pipelet_option_gain_cost(
                    pipelet1_options[i],
                    mcost=random.randint(1, (mavail // config.DP_MSTEP) // 3),
                    icost=random.randint(1, (iavail // config.DP_ISTEP) // 3),
                    lgain=lgain,
                    tgain=1,
                )
            max_gain2 = -1
            best_option2 = []
            for i in range(len(pipelet2_options)):
                lgain = random.randint(1, 100)
                if lgain > max_gain2:
                    max_gain2 = lgain
                    best_option2 = [pipelet2_options[i]]
                elif lgain == max_gain2:
                    best_option2.append(pipelet2_options[i])
                utils.set_pipelet_option_gain_cost(
                    pipelet2_options[i],
                    mcost=random.randint(1, (mavail // config.DP_MSTEP) // 3),
                    icost=random.randint(1, (iavail // config.DP_ISTEP) // 3),
                    lgain=lgain,
                    tgain=1,
                )

            res = PipeletOptimizer._compute_best_global_plan_dp(
                mavail, iavail, OptimizeTarget.LATENCY, [pipelet1_options, pipelet2_options]
            )
            assert res != None and len(res.option) == 2
            assert (res.option[0] in best_option1 and res.option[1] in best_option2) or (
                res.option[1] in best_option1 and res.option[0] in best_option2
            )

    def test_two_pipelets_partial_within_resources(self, mock_gain_cost):
        for _ in range(50):
            pipelet1 = utils.create_pipelet_asic_static_small(2, MatchType.TERNARY)
            pipelet2 = utils.create_pipelet_asic_static_small(2, MatchType.TERNARY)
            optimize_method = [
                OptimizeMethod.REORDER,
                OptimizeMethod.SOFTCOPY,
                OptimizeMethod.MERGE,
                OptimizeMethod.CACHE,
                OptimizeMethod.SOFTMOVE,
            ]
            pipelet1_options = PipeletOptimizer._compute_all_options(pipelet1, optimize_method)
            pipelet2_options = PipeletOptimizer._compute_all_options(pipelet2, optimize_method)
            mock_gain_cost.assert_called()
            assert len(pipelet1_options) == 11 and len(pipelet2_options) == 11
            mavail, iavail = TOTAL_MEMORY, TOTAL_ENTRY_INSERTION
            max_gain1 = -1
            best_option1 = []
            for i in range(len(pipelet1_options)):
                lgain = random.randint(1, 100)
                if lgain > max_gain1:
                    max_gain1 = lgain
                    best_option1 = [pipelet1_options[i]]
                elif lgain == max_gain1:
                    best_option1.append(pipelet1_options[i])
                utils.set_pipelet_option_gain_cost(
                    pipelet1_options[i],
                    mcost=random.randint((mavail) // 2, mavail - config.DP_MSTEP - 1),
                    icost=random.randint((iavail) // 2, iavail - config.DP_ISTEP - 1),
                    lgain=lgain,
                    tgain=1,
                )
            max_gain2 = -1
            best_option2 = []
            for i in range(len(pipelet2_options)):
                lgain = random.randint(1, 100)
                if lgain > max_gain2:
                    max_gain2 = lgain
                    best_option2 = [pipelet2_options[i]]
                elif lgain == max_gain2:
                    best_option2.append(pipelet2_options[i])
                utils.set_pipelet_option_gain_cost(
                    pipelet2_options[i],
                    mcost=random.randint((mavail) // 2, mavail - config.DP_MSTEP - 1),
                    icost=random.randint((iavail) // 2, iavail - config.DP_ISTEP - 1),
                    lgain=lgain,
                    tgain=1,
                )

            res = PipeletOptimizer._compute_best_global_plan_dp(
                mavail, iavail, OptimizeTarget.LATENCY, [pipelet1_options, pipelet2_options]
            )
            assert res != None and len(res.option) == 1

            if max_gain1 > max_gain2:
                assert res.option[0] in best_option1
            elif max_gain1 < max_gain2:
                assert res.option[0] in best_option2
            else:
                assert res.option[0] in best_option1 + best_option2

    def test_two_pipelets_beyond_resources(self, mock_gain_cost):
        for _ in range(50):
            pipelet1 = utils.create_pipelet_asic_static_small(2, MatchType.TERNARY)
            pipelet2 = utils.create_pipelet_asic_static_small(2, MatchType.TERNARY)
            optimize_method = [
                OptimizeMethod.REORDER,
                OptimizeMethod.SOFTCOPY,
                OptimizeMethod.MERGE,
                OptimizeMethod.CACHE,
                OptimizeMethod.SOFTMOVE,
            ]
            pipelet1_options = PipeletOptimizer._compute_all_options(pipelet1, optimize_method)
            pipelet2_options = PipeletOptimizer._compute_all_options(pipelet2, optimize_method)
            mock_gain_cost.assert_called()
            assert len(pipelet1_options) == 11 and len(pipelet2_options) == 11
            mavail, iavail = TOTAL_MEMORY, TOTAL_ENTRY_INSERTION
            max_gain1 = -1
            best_option1 = []
            for i in range(len(pipelet1_options)):
                lgain = random.randint(1, 100)
                if lgain > max_gain1:
                    max_gain1 = lgain
                    best_option1 = [pipelet1_options[i]]
                elif lgain == max_gain1:
                    best_option1.append(pipelet1_options[i])
                utils.set_pipelet_option_gain_cost(
                    pipelet1_options[i],
                    mcost=random.randint(mavail, mavail * 2),
                    icost=random.randint(iavail, iavail * 2),
                    lgain=lgain,
                    tgain=1,
                )
            max_gain2 = -1
            best_option2 = []
            for i in range(len(pipelet2_options)):
                lgain = random.randint(1, 100)
                if lgain > max_gain2:
                    max_gain2 = lgain
                    best_option2 = [pipelet2_options[i]]
                elif lgain == max_gain2:
                    best_option2.append(pipelet2_options[i])
                utils.set_pipelet_option_gain_cost(
                    pipelet2_options[i],
                    mcost=random.randint(mavail, mavail * 2),
                    icost=random.randint(iavail, iavail * 2),
                    lgain=lgain,
                    tgain=1,
                )

            res = PipeletOptimizer._compute_best_global_plan_dp(
                mavail, iavail, OptimizeTarget.LATENCY, [pipelet1_options, pipelet2_options]
            )
            assert res == None

    def _create_random_pipelet_options(
        self, table_num: int, mavail: int, iavail: int
    ) -> Tuple[Pipelet, List[PipeletOption]]:
        pipelet = utils.create_pipelet_asic_static_small(table_num, MatchType.TERNARY)
        optimize_method = [
            OptimizeMethod.REORDER,
            OptimizeMethod.SOFTCOPY,
            OptimizeMethod.MERGE,
            OptimizeMethod.CACHE,
            OptimizeMethod.SOFTMOVE,
        ]
        pipelet_options = PipeletOptimizer._compute_all_options(pipelet, optimize_method)
        for i in range(len(pipelet_options)):
            lgain = random.randint(1, 100)
            tgain = random.randint(1, 100)
            utils.set_pipelet_option_gain_cost(
                pipelet_options[i],
                mcost=random.randint(1, mavail - config.DP_MSTEP - 1),
                icost=random.randint(1, iavail - config.DP_ISTEP - 1),
                lgain=lgain,
                tgain=tgain,
            )
        return pipelet, pipelet_options

    def _validate_combined_opts(self, combination: List[PipeletOption]) -> bool:
        selected_pipelet = []
        # Each pipelet can only be optimized by one option
        for comb in combination:
            if comb.pipelet not in selected_pipelet:
                selected_pipelet.append(comb)
            else:
                return False
        return True

    def test_random_pipelets_latency(self, mock_gain_cost):
        for _ in range(10):
            mavail, iavail = TOTAL_MEMORY, TOTAL_ENTRY_INSERTION
            pipelet1, pipelet1_options = self._create_random_pipelet_options(3, mavail, iavail)
            pipelet2, pipelet2_options = self._create_random_pipelet_options(3, mavail, iavail)
            pipelet3, pipelet3_options = self._create_random_pipelet_options(3, mavail, iavail)

            best_lgain = -1
            best_tgain = -1

            for i in range(-1, len(pipelet1_options)):
                pipelet1_selected = None if i == -1 else pipelet1_options[i]
                for j in range(-1, len(pipelet2_options)):
                    pipelet2_selected = None if j == -1 else pipelet2_options[j]
                    for k in range(-1, len(pipelet3_options)):
                        pipelet3_selected = None if k == -1 else pipelet3_options[k]
                        combination = []
                        if pipelet1_selected:
                            combination.append(pipelet1_selected)
                        if pipelet2_selected:
                            combination.append(pipelet2_selected)
                        if pipelet3_selected:
                            combination.append(pipelet3_selected)

                        total_mcost = 0
                        total_icost = 0
                        total_lgain = 0
                        total_tgain = 0
                        for comb in combination:
                            opt_mcost = (comb.mcost - comb.mcost % config.DP_MSTEP) + config.DP_MSTEP
                            opt_icost = (comb.icost - comb.icost % config.DP_ISTEP) + config.DP_ISTEP
                            total_mcost += opt_mcost
                            total_icost += opt_icost
                            total_lgain += comb.lgain
                            total_tgain += comb.tgain

                        if total_mcost > mavail or total_icost > iavail:
                            continue
                        if total_lgain > best_lgain:
                            best_lgain = total_lgain
                        if total_tgain > best_tgain:
                            best_tgain = total_tgain

            res = PipeletOptimizer._compute_best_global_plan_dp(
                mavail, iavail, OptimizeTarget.LATENCY, [pipelet1_options, pipelet2_options, pipelet3_options]
            )
            assert res != None
            assert res.gain == best_lgain

    def test_random_pipelets_throughput(self, mock_gain_cost):
        for _ in range(10):
            mavail, iavail = TOTAL_MEMORY, TOTAL_ENTRY_INSERTION
            pipelet1, pipelet1_options = self._create_random_pipelet_options(3, mavail, iavail)
            pipelet2, pipelet2_options = self._create_random_pipelet_options(3, mavail, iavail)
            pipelet3, pipelet3_options = self._create_random_pipelet_options(3, mavail, iavail)

            best_lgain = -1
            best_tgain = -1

            for i in range(-1, len(pipelet1_options)):
                pipelet1_selected = None if i == -1 else pipelet1_options[i]
                for j in range(-1, len(pipelet2_options)):
                    pipelet2_selected = None if j == -1 else pipelet2_options[j]
                    for k in range(-1, len(pipelet3_options)):
                        pipelet3_selected = None if k == -1 else pipelet3_options[k]
                        combination = []
                        if pipelet1_selected:
                            combination.append(pipelet1_selected)
                        if pipelet2_selected:
                            combination.append(pipelet2_selected)
                        if pipelet3_selected:
                            combination.append(pipelet3_selected)

                        total_mcost = 0
                        total_icost = 0
                        total_lgain = 0
                        total_tgain = 0
                        for comb in combination:
                            opt_mcost = (comb.mcost - comb.mcost % config.DP_MSTEP) + config.DP_MSTEP
                            opt_icost = (comb.icost - comb.icost % config.DP_ISTEP) + config.DP_ISTEP
                            total_mcost += opt_mcost
                            total_icost += opt_icost
                            total_lgain += comb.lgain
                            total_tgain += comb.tgain

                        if total_mcost > mavail or total_icost > iavail:
                            continue
                        if total_lgain > best_lgain:
                            best_lgain = total_lgain
                        if total_tgain > best_tgain:
                            best_tgain = total_tgain

            res = PipeletOptimizer._compute_best_global_plan_dp(
                mavail, iavail, OptimizeTarget.THROUGHT, [pipelet1_options, pipelet2_options, pipelet3_options]
            )
            assert res != None
            assert res.gain == best_tgain


@pytest.mark.parametrize(
    "reorder_json_path",
    [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "reorder", "test.p4.json")],
)
@patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
class TestDpAlgorithmWithStatsReorder:
    def test_reorder_with_drop_rate(self, retrieve_runtime_states, reorder_json_path):
        irg, target = JsonManager.retrieve_presplit(reorder_json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
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
        expected_option = PipeletOptimizer.create_pipelet_option(
            JsonPlanner.get_pipelets(ingress_graph)[0], ReorderOption([2, 1, 0]), None
        )
        assert pipelet_options.option[0].lgain == expected_option.lgain

    def test_reorder_with_drop_rate_random(self, retrieve_runtime_states, reorder_json_path):
        for _ in range(10):
            irg, target = JsonManager.retrieve_presplit(reorder_json_path)
            JsonManager.compile_time_json_planning(irg)
            ingress_graph = irg.get_pipe("ingress")
            tables = list(ingress_graph.tables)
            total_pkt = 100
            drop_counts = {i: random.randint(0, 100) for i in range(len(tables))}
            tns = [t.name for t in tables]
            retrieve_runtime_states.return_value = RuntimeStates(
                table_to_counts={
                    tns[0]: utils._gen_count_profile_reorder(tables[0], drop_counts[0], total_pkt),
                    tns[1]: utils._gen_count_profile_reorder(tables[1], drop_counts[1], total_pkt),
                    tns[2]: utils._gen_count_profile_reorder(tables[2], drop_counts[2], total_pkt),
                },
                cond_to_counts={},
                table_to_size={tns[0]: 1, tns[1]: 1, tns[2]: 1},
                table_to_entry_insertion_count={tns[0]: 1, tns[1]: 1, tns[2]: 1},
                total_memory=TOTAL_MEMORY,
                total_entry_insertion_bandwidth=TOTAL_ENTRY_INSERTION,
                mapping_dict={"tables": {t.name: {"entries": utils._gen_entries_json()} for t in tables}},
            )
            pipelet_options = utils._call_optimizer(irg, [OptimizeMethod.REORDER], OptimizeTarget.LATENCY)

            drop_counts_sorted = OrderedDict(sorted(drop_counts.items(), key=lambda t: t[1], reverse=True))
            expected_option = PipeletOptimizer.create_pipelet_option(
                JsonPlanner.get_pipelets(ingress_graph)[0], ReorderOption(list(drop_counts_sorted.keys())), None
            )
            # the same order, no plan
            if list(drop_counts.keys()) == list(drop_counts_sorted.keys()):
                assert pipelet_options == None
            else:
                # no gain, no plan
                if expected_option.lgain <= 0:
                    assert pipelet_options == None
                else:
                    assert pipelet_options != None
                    assert len(pipelet_options.option) == 1
                    assert pipelet_options.option[0].lgain == expected_option.lgain

    def test_reorder_no_change(self, retrieve_runtime_states, reorder_json_path):
        irg, target = JsonManager.retrieve_presplit(reorder_json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        tns = [t.name for t in tables]
        retrieve_runtime_states.return_value = RuntimeStates(
            table_to_counts={
                tns[0]: utils._gen_count_profile_reorder(tables[0], 0, 10),
                tns[1]: utils._gen_count_profile_reorder(tables[1], 0, 10),
                tns[2]: utils._gen_count_profile_reorder(tables[2], 0, 10),
            },
            cond_to_counts={},
            table_to_size={tns[0]: 1, tns[1]: 1, tns[2]: 1},
            table_to_entry_insertion_count={tns[0]: 1, tns[1]: 1, tns[2]: 1},
            total_memory=TOTAL_MEMORY,
            total_entry_insertion_bandwidth=TOTAL_ENTRY_INSERTION,
            mapping_dict={"tables": {t.name: {"entries": utils._gen_entries_json()} for t in tables}},
        )
        pipelet_options = utils._call_optimizer(irg, [OptimizeMethod.REORDER], OptimizeTarget.LATENCY)
        assert pipelet_options == None


SW_LATENCY = 200
HW_LATENCY = 100


@pytest.mark.parametrize(
    "copy_json_path",
    [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "softcopy", "test.p4.json")],
)
@patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
@patch("targets.smart_nic.SwSteering.latency_eval")
@patch("targets.smart_nic.HwSteering.latency_eval")
class TestDpAlgorithmWithStatsSoftcopySoftmove:
    def fake_sw_latency_eval(self, table: Table) -> LatencyPdf:
        latency_list: LatencyPdf = []
        num_actions = len(table.action_ids)
        for _ in range(num_actions):
            prob = 1.0 / num_actions
            latencies_list_add_item(latency_list, SW_LATENCY, prob)
        return latency_list

    def fake_hw_latency_eval(self, table: Table) -> LatencyPdf:
        latency_list: LatencyPdf = []
        num_actions = len(table.action_ids)
        for _ in range(num_actions):
            prob = 1.0 / num_actions
            latencies_list_add_item(latency_list, HW_LATENCY, prob)
        return latency_list

    def test_softcopy_tag(self, hw_latency_eval, sw_latency_eval, retrieve_runtime_states, copy_json_path):
        irg, target = JsonManager.retrieve_presplit(copy_json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        conds = list(ingress_graph.conditions)
        retrieve_runtime_states.return_value = utils.gen_runtime_stats(tables, conds)
        sw_latency_eval.side_effect = self.fake_sw_latency_eval
        hw_latency_eval.side_effect = self.fake_hw_latency_eval

        pipelet_options = utils._call_optimizer(
            irg, [OptimizeMethod.SOFTCOPY, OptimizeMethod.SOFTMOVE], OptimizeTarget.LATENCY
        )

        sw_latency_eval.assert_called()
        hw_latency_eval.assert_called()

        # When the latency gain is computed by -1 * delta._median_latency
        # assert pipelet_options is None

        # When the latency gain is computed by -1*(0.5*delta._median_latency + 0.5*delta._p99_latency)
        assert pipelet_options != None and len(pipelet_options.option) == 1
        pipelet_options = pipelet_options.option
        assert len(pipelet_options) == 1
        comb_options = pipelet_options[0].combined_options
        assert comb_options != None and len(comb_options) == 1
        assert comb_options[0].start_table_id == 2 and comb_options[0].length == 1

    def test_softcopy_none(self, hw_latency_eval, sw_latency_eval, retrieve_runtime_states, copy_json_path):
        global SW_LATENCY, HW_LATENCY
        SW_LATENCY = 2000
        HW_LATENCY = 100
        irg, target = JsonManager.retrieve_presplit(copy_json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        conds = list(ingress_graph.conditions)
        retrieve_runtime_states.return_value = utils.gen_runtime_stats(tables, conds)
        sw_latency_eval.side_effect = self.fake_sw_latency_eval
        hw_latency_eval.side_effect = self.fake_hw_latency_eval

        pipelet_options = utils._call_optimizer(
            irg, [OptimizeMethod.SOFTCOPY, OptimizeMethod.SOFTMOVE], OptimizeTarget.LATENCY
        )

        sw_latency_eval.assert_called()
        hw_latency_eval.assert_called()

        assert pipelet_options == None

    @pytest.mark.parametrize(
        "copy_json_path2",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "softcopy2", "test.p4.json")],
    )
    @patch("targets.target_base.MultiTargetBase.get_mitigation_latency")
    def test_softcopy_forward_and_tag(
        self, migration_lat, hw_latency_eval, sw_latency_eval, retrieve_runtime_states, copy_json_path2, copy_json_path
    ):
        global SW_LATENCY, HW_LATENCY
        SW_LATENCY = 10
        HW_LATENCY = 200
        migration_lat.return_value = 10
        irg, target = JsonManager.retrieve_presplit(copy_json_path2)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        conds = list(ingress_graph.conditions)
        retrieve_runtime_states.return_value = utils.gen_runtime_stats(tables, conds)
        sw_latency_eval.side_effect = self.fake_sw_latency_eval
        hw_latency_eval.side_effect = self.fake_hw_latency_eval

        pipelet_options = utils._call_optimizer(
            irg, [OptimizeMethod.SOFTCOPY, OptimizeMethod.SOFTMOVE], OptimizeTarget.LATENCY
        )

        sw_latency_eval.assert_called()
        hw_latency_eval.assert_called()
        migration_lat.assert_called()

        assert pipelet_options != None and len(pipelet_options.option) == 1
        pipelet_options = pipelet_options.option
        assert len(pipelet_options) == 1
        comb_options = pipelet_options[0].combined_options
        assert comb_options != None and len(comb_options) == 3
        assert comb_options[0].start_table_id == 2 and comb_options[0].length == 1
        assert comb_options[1].start_table_id == 0 and comb_options[1].length == 1
        assert comb_options[2].start_table_id == 4 and comb_options[2].length == 1

    @pytest.mark.parametrize(
        "copy_json_path2",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "consecutive_copy", "test.p4.json")],
    )
    @patch("targets.target_base.MultiTargetBase.get_mitigation_latency")
    def test_softcopy_consecutive(
        self, migration_lat, hw_latency_eval, sw_latency_eval, retrieve_runtime_states, copy_json_path2, copy_json_path
    ):
        global SW_LATENCY, HW_LATENCY
        SW_LATENCY = 10
        HW_LATENCY = 200
        migration_lat.return_value = 10
        irg, target = JsonManager.retrieve_presplit(copy_json_path2)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        conds = list(ingress_graph.conditions)
        retrieve_runtime_states.return_value = utils.gen_runtime_stats(tables, conds)
        sw_latency_eval.side_effect = self.fake_sw_latency_eval
        hw_latency_eval.side_effect = self.fake_hw_latency_eval

        pipelet_options = utils._call_optimizer(
            irg, [OptimizeMethod.SOFTCOPY, OptimizeMethod.SOFTMOVE], OptimizeTarget.LATENCY
        )

        sw_latency_eval.assert_called()
        hw_latency_eval.assert_called()
        migration_lat.assert_called()

        assert pipelet_options != None and len(pipelet_options.option) == 1
        pipelet_options = pipelet_options.option
        assert len(pipelet_options) == 1
        comb_options = pipelet_options[0].combined_options
        assert comb_options != None and len(comb_options) == 2
        assert comb_options[0].start_table_id == 2 and comb_options[0].length == 2
        assert comb_options[1].start_table_id == 0 and comb_options[1].length == 1


@patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
class TestDpAlgorithmReal:
    @pytest.mark.parametrize(
        "json_path", [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "softcopy", "test.p4.json")]
    )
    def test_reorder_softcopy_softmove(self, retrieve_runtime_states, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        conds = list(ingress_graph.conditions)
        retrieve_runtime_states.return_value = utils.gen_runtime_stats(tables, conds)

        optimize_method = [
            OptimizeMethod.REORDER,
            OptimizeMethod.SOFTCOPY,
            OptimizeMethod.SOFTMOVE,
        ]
        pipelet_options = utils._call_optimizer(irg, optimize_method, OptimizeTarget.LATENCY)
        print(pipelet_options)
