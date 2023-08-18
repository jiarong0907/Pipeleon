import math
import os
from graph_optimizer.pipelet import Pipelet, PipeletGroup
from ir.condition import Condition
import pytest
from typing import List, Set, Tuple

from commons.types import Probability
import commons.config as config
from graph_optimizer.json_manager import JsonManager
from graph_optimizer.metadata import CacheMetadata, GroupCacheMetadata, MergeMetadata
from graph_optimizer.opt_utils import OptUtils
from ir.action import OptAction
from ir.match_key import MatchKey, MatchType
from ir.table import Table
import mock_import
from runtime_CLI import RuntimeAPI


@pytest.mark.parametrize(
    "json_path", [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "merge", "test.p4.json")]
)
class TestMerge:
    def test_create_merge_table_exact_exact(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 2
        exact_tab1 = tables[0]
        exact_tab2 = tables[1]
        assert isinstance(exact_tab1, Table) and isinstance(exact_tab2, Table)
        exact_tab1.optimized_metadata = MergeMetadata(
            start_table_id=0, length=2, merged_tables=[exact_tab1, exact_tab2]
        )
        exact_tab1.update_prob_with_counts({"MyIngress.tab_exact1_act1": 60, "MyIngress.tab_exact1_act2": 40})
        exact_tab2.update_prob_with_counts({"MyIngress.tab_exact2_act1": 70, "MyIngress.tab_exact2_act2": 30})
        exact_tab1.current_size = 10
        exact_tab2.current_size = 20
        exact_tab1.entry_insertion_rate = 20
        exact_tab2.entry_insertion_rate = 10
        merged_table = exact_tab1._create_merge_table(irg, ingress_graph, "merged_table")

        assert merged_table.name == "merged_table"
        merged_act_names = merged_table.action_names
        assert merged_act_names[0] == "merged_MyIngress.tab_exact1_act1_MyIngress.tab_exact2_act1"
        assert merged_act_names[1] == "merged_MyIngress.tab_exact1_act1_MyIngress.tab_exact2_act2"
        assert merged_act_names[2] == "merged_MyIngress.tab_exact1_act2_MyIngress.tab_exact2_act1"
        assert merged_act_names[3] == "merged_MyIngress.tab_exact1_act2_MyIngress.tab_exact2_act2"
        merged_keys = merged_table.keys
        assert len(merged_keys) == 4
        for mkey in merged_keys:
            assert mkey.match_type == MatchType.EXACT
        assert merged_keys[0].header == "tcp.srcPort"
        assert merged_keys[1].header == "ipv4.srcAddr"
        assert merged_keys[2].header == "tcp.dstPort"
        assert merged_keys[3].header == "ipv4.dstAddr"
        assert merged_table.default_action_name == "NoAction"
        assert merged_table._default_action_const == False
        assert merged_table._default_action_param == []
        assert merged_table._default_action_entry_const == False
        assert 0.41 > merged_table.action_to_probability[merged_act_names[0]] > 0.39
        assert 0.18 > merged_table.action_to_probability[merged_act_names[1]] > 0.16
        assert 0.27 > merged_table.action_to_probability[merged_act_names[2]] > 0.26
        assert 0.12 > merged_table.action_to_probability[merged_act_names[3]] > 0.11
        assert 0.051 > merged_table.action_to_probability[merged_table.default_action_name] > 0.049

    def test_create_merge_table_exact_lpm(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 3
        exact_tab1 = tables[0]
        lpm_tab1 = tables[2]
        assert isinstance(exact_tab1, Table) and isinstance(lpm_tab1, Table)
        exact_tab1.optimized_metadata = MergeMetadata(start_table_id=0, length=2, merged_tables=[exact_tab1, lpm_tab1])
        exact_tab1.update_prob_with_counts({"MyIngress.tab_exact1_act1": 50, "MyIngress.tab_exact1_act2": 50})
        lpm_tab1.update_prob_with_counts({"MyIngress.tab_lpm1_act1": 70, "MyIngress.tab_lpm1_act2": 20, "NoAction": 10})
        exact_tab1.current_size = 10
        lpm_tab1.current_size = 20
        exact_tab1.entry_insertion_rate = 20
        lpm_tab1.entry_insertion_rate = 10
        merged_table = exact_tab1._create_merge_table(irg, ingress_graph, "merged_table")

        assert merged_table.name == "merged_table"
        merged_act_names = merged_table.action_names
        assert merged_act_names[0] == "merged_MyIngress.tab_exact1_act1_MyIngress.tab_lpm1_act1"
        assert merged_act_names[1] == "merged_MyIngress.tab_exact1_act1_MyIngress.tab_lpm1_act2"
        assert merged_act_names[2] == "merged_MyIngress.tab_exact1_act1_NoAction"
        assert merged_act_names[3] == "merged_MyIngress.tab_exact1_act2_MyIngress.tab_lpm1_act1"
        assert merged_act_names[4] == "merged_MyIngress.tab_exact1_act2_MyIngress.tab_lpm1_act2"
        assert merged_act_names[5] == "merged_MyIngress.tab_exact1_act2_NoAction"
        merged_keys = merged_table.keys
        assert len(merged_keys) == 3
        assert merged_keys[0].match_type == MatchType.EXACT
        assert merged_keys[1].match_type == MatchType.EXACT
        assert merged_keys[2].match_type == MatchType.LPM
        assert merged_keys[0].header == "tcp.srcPort"
        assert merged_keys[1].header == "ipv4.srcAddr"
        assert merged_keys[2].header == "ipv4.dstAddr"
        assert merged_table.default_action_name == "NoAction"
        assert merged_table._default_action_const == False
        assert merged_table._default_action_param == []
        assert merged_table._default_action_entry_const == False
        assert 0.34 > merged_table.action_to_probability[merged_act_names[0]] > 0.33
        assert 0.11 > merged_table.action_to_probability[merged_act_names[1]] > 0.09
        assert 0.05 > merged_table.action_to_probability[merged_act_names[2]] > 0.04
        assert 0.34 > merged_table.action_to_probability[merged_act_names[3]] > 0.33
        assert 0.11 > merged_table.action_to_probability[merged_act_names[4]] > 0.09
        assert 0.05 > merged_table.action_to_probability[merged_act_names[5]] > 0.04

    def test_create_merge_table_exact_ternary(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 4
        exact_tab1 = tables[0]
        ternary_tab1 = tables[3]
        assert isinstance(exact_tab1, Table) and isinstance(ternary_tab1, Table)
        exact_tab1.optimized_metadata = MergeMetadata(
            start_table_id=0, length=2, merged_tables=[exact_tab1, ternary_tab1]
        )
        exact_tab1.update_prob_with_counts({"MyIngress.tab_exact1_act1": 50, "MyIngress.tab_exact1_act2": 50})
        ternary_tab1.update_prob_with_counts(
            {"MyIngress.tab_ternary1_act1": 70, "MyIngress.tab_ternary1_act2": 20, "NoAction": 10}
        )
        exact_tab1.current_size = 10
        ternary_tab1.current_size = 20
        exact_tab1.entry_insertion_rate = 20
        ternary_tab1.entry_insertion_rate = 10
        merged_table = exact_tab1._create_merge_table(irg, ingress_graph, "merged_table")

        assert merged_table.name == "merged_table"
        merged_act_names = merged_table.action_names
        assert merged_act_names[0] == "merged_MyIngress.tab_exact1_act1_MyIngress.tab_ternary1_act1"
        assert merged_act_names[1] == "merged_MyIngress.tab_exact1_act1_MyIngress.tab_ternary1_act2"
        assert merged_act_names[2] == "merged_MyIngress.tab_exact1_act1_NoAction"
        assert merged_act_names[3] == "merged_MyIngress.tab_exact1_act2_MyIngress.tab_ternary1_act1"
        assert merged_act_names[4] == "merged_MyIngress.tab_exact1_act2_MyIngress.tab_ternary1_act2"
        assert merged_act_names[5] == "merged_MyIngress.tab_exact1_act2_NoAction"
        merged_keys = merged_table.keys
        assert len(merged_keys) == 3
        assert merged_keys[0].match_type == MatchType.TERNARY
        assert merged_keys[1].match_type == MatchType.TERNARY
        assert merged_keys[2].match_type == MatchType.TERNARY
        assert merged_keys[0].header == "tcp.srcPort"
        assert merged_keys[1].header == "ipv4.srcAddr"
        assert merged_keys[2].header == "ipv4.srcAddr"
        assert merged_table.default_action_name == "NoAction"
        assert merged_table._default_action_const == False
        assert merged_table._default_action_param == []
        assert merged_table._default_action_entry_const == False
        assert merged_table.action_to_probability[merged_act_names[0]] == 0.35
        assert merged_table.action_to_probability[merged_act_names[1]] == 0.10
        assert merged_table.action_to_probability[merged_act_names[2]] == 0.05
        assert merged_table.action_to_probability[merged_act_names[3]] == 0.35
        assert merged_table.action_to_probability[merged_act_names[4]] == 0.10
        assert merged_table.action_to_probability[merged_act_names[5]] == 0.05

    def test_create_merge_table_lpm_ternary(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 4
        lpm_tab1 = tables[2]
        ternary_tab1 = tables[3]
        assert isinstance(lpm_tab1, Table) and isinstance(ternary_tab1, Table)
        lpm_tab1.optimized_metadata = MergeMetadata(start_table_id=0, length=2, merged_tables=[lpm_tab1, ternary_tab1])
        lpm_tab1.update_prob_with_counts({"MyIngress.tab_lpm1_act1": 70, "MyIngress.tab_lpm1_act2": 20, "NoAction": 10})
        ternary_tab1.update_prob_with_counts(
            {"MyIngress.tab_ternary1_act1": 40, "MyIngress.tab_ternary1_act2": 40, "NoAction": 20}
        )
        lpm_tab1.current_size = 10
        ternary_tab1.current_size = 20
        lpm_tab1.entry_insertion_rate = 20
        ternary_tab1.entry_insertion_rate = 10
        merged_table = lpm_tab1._create_merge_table(irg, ingress_graph, "merged_table")

        assert merged_table.name == "merged_table"
        merged_act_names = merged_table.action_names
        assert merged_act_names[0] == "merged_MyIngress.tab_lpm1_act1_MyIngress.tab_ternary1_act1"
        assert merged_act_names[1] == "merged_MyIngress.tab_lpm1_act1_MyIngress.tab_ternary1_act2"
        assert merged_act_names[2] == "merged_MyIngress.tab_lpm1_act1_NoAction"
        assert merged_act_names[3] == "merged_MyIngress.tab_lpm1_act2_MyIngress.tab_ternary1_act1"
        assert merged_act_names[4] == "merged_MyIngress.tab_lpm1_act2_MyIngress.tab_ternary1_act2"
        assert merged_act_names[5] == "merged_MyIngress.tab_lpm1_act2_NoAction"
        assert merged_act_names[6] == "merged_NoAction_MyIngress.tab_ternary1_act1"
        assert merged_act_names[7] == "merged_NoAction_MyIngress.tab_ternary1_act2"
        assert merged_act_names[8] == "merged_NoAction_NoAction"
        merged_keys = merged_table.keys
        assert len(merged_keys) == 2
        assert merged_keys[0].match_type == MatchType.TERNARY
        assert merged_keys[1].match_type == MatchType.TERNARY
        assert merged_keys[0].header == "ipv4.dstAddr"
        assert merged_keys[1].header == "ipv4.srcAddr"
        assert merged_table.default_action_name == "NoAction"
        assert merged_table._default_action_const == False
        assert merged_table._default_action_param == []
        assert merged_table._default_action_entry_const == False
        assert merged_table.action_to_probability[merged_act_names[0]] == 0.28
        assert merged_table.action_to_probability[merged_act_names[1]] == 0.28
        assert merged_table.action_to_probability[merged_act_names[2]] == 0.14
        assert merged_table.action_to_probability[merged_act_names[3]] == 0.08
        assert merged_table.action_to_probability[merged_act_names[4]] == 0.08
        assert merged_table.action_to_probability[merged_act_names[5]] == 0.04
        assert merged_table.action_to_probability[merged_act_names[6]] == 0.04
        assert merged_table.action_to_probability[merged_act_names[7]] == 0.04
        assert merged_table.action_to_probability[merged_act_names[8]] == 0.02

    def test_create_merge_table_ternary_ternary(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 5
        ternary_tab1 = tables[3]
        ternary_tab2 = tables[4]
        assert isinstance(ternary_tab1, Table) and isinstance(ternary_tab2, Table)
        ternary_tab1.optimized_metadata = MergeMetadata(
            start_table_id=0, length=2, merged_tables=[ternary_tab1, ternary_tab2]
        )
        ternary_tab1.current_size = 10
        ternary_tab2.current_size = 20
        ternary_tab1.entry_insertion_rate = 20
        ternary_tab2.entry_insertion_rate = 10
        merged_table = ternary_tab1._create_merge_table(irg, ingress_graph, "merged_table")

        assert merged_table.name == "merged_table"
        merged_act_names = merged_table.action_names
        assert merged_act_names[0] == "merged_MyIngress.tab_ternary1_act1_MyIngress.tab_ternary2_act1"
        assert merged_act_names[1] == "merged_MyIngress.tab_ternary1_act1_MyIngress.tab_ternary2_act2"
        assert merged_act_names[2] == "merged_MyIngress.tab_ternary1_act2_MyIngress.tab_ternary2_act1"
        assert merged_act_names[3] == "merged_MyIngress.tab_ternary1_act2_MyIngress.tab_ternary2_act2"
        assert merged_act_names[4] == "merged_NoAction_MyIngress.tab_ternary2_act1"
        assert merged_act_names[5] == "merged_NoAction_MyIngress.tab_ternary2_act2"
        merged_keys = merged_table.keys
        assert len(merged_keys) == 2
        assert merged_keys[0].match_type == MatchType.TERNARY
        assert merged_keys[1].match_type == MatchType.TERNARY
        assert merged_keys[0].header == "ipv4.srcAddr"
        assert merged_keys[1].header == "ipv4.dstAddr"
        assert merged_table.default_action_name == "NoAction"
        assert merged_table._default_action_const == False
        assert merged_table._default_action_param == []
        assert merged_table._default_action_entry_const == False

    def test_create_merge_table_exact_mix(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 6
        exact_tab1 = tables[0]
        mix_tab1 = tables[5]
        assert isinstance(exact_tab1, Table) and isinstance(mix_tab1, Table)
        exact_tab1.optimized_metadata = MergeMetadata(start_table_id=0, length=2, merged_tables=[exact_tab1, mix_tab1])
        exact_tab1.current_size = 10
        mix_tab1.current_size = 20
        exact_tab1.entry_insertion_rate = 20
        mix_tab1.entry_insertion_rate = 10

        merged_table = exact_tab1._create_merge_table(irg, ingress_graph, "merged_table")

        assert merged_table.name == "merged_table"
        merged_act_names = merged_table.action_names
        assert merged_act_names[0] == "merged_MyIngress.tab_exact1_act1_MyIngress.tab_mix_act1"
        assert merged_act_names[1] == "merged_MyIngress.tab_exact1_act1_MyIngress.tab_mix_act2"
        assert merged_act_names[2] == "merged_MyIngress.tab_exact1_act2_MyIngress.tab_mix_act1"
        assert merged_act_names[3] == "merged_MyIngress.tab_exact1_act2_MyIngress.tab_mix_act2"
        merged_keys = merged_table.keys
        assert len(merged_keys) == 6
        for mkey in merged_keys:
            assert mkey.match_type == MatchType.TERNARY
        assert merged_keys[0].header == "tcp.srcPort"
        assert merged_keys[1].header == "ipv4.srcAddr"
        assert merged_keys[2].header == "tcp.srcPort"
        assert merged_keys[3].header == "migration.addr1"
        assert merged_keys[4].header == "ipv4.srcAddr"
        assert merged_keys[5].header == "ipv4.dstAddr"
        assert merged_table.default_action_name == "NoAction"
        assert merged_table._default_action_const == False
        assert merged_table._default_action_param == []
        assert merged_table._default_action_entry_const == False


@pytest.mark.parametrize(
    "json_path",
    [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "strict_match_dependency", "test.p4.json")],
)
class TestCache:
    def test_cache_one_table(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 3
        tab1 = tables[1]
        assert isinstance(tab1, Table)
        tab1.optimized_metadata = CacheMetadata(start_table_id=1, length=1, cached_tables=[tab1])
        tab1.update_prob_with_counts({"MyIngress.tab2_act1": 60, "MyIngress.tab2_act2": 40})
        cache_table = tab1._create_cache_table(irg, ingress_graph, "cache_table")
        assert cache_table.name == "cache_table"
        cache_act_names = cache_table.action_names
        assert cache_act_names[0] == "merged_MyIngress.tab2_act1"
        assert cache_act_names[1] == "merged_MyIngress.tab2_act2"
        cache_keys = cache_table.keys
        assert len(cache_keys) == 2
        assert set([ckey.header for ckey in cache_keys]) == set(["migration.tabl1_data", "scalars.userMetadata.aaa"])
        assert cache_table.default_action_name == "NoAction"
        assert cache_table._default_action_const == False
        assert cache_table._default_action_param == []
        assert cache_table._default_action_entry_const == False
        assert 0.58 > cache_table.action_to_probability[cache_act_names[0]] > 0.57
        assert 0.39 > cache_table.action_to_probability[cache_act_names[1]] > 0.38

    def test_cache_two_tables(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 3
        tab0 = tables[0]
        tab1 = tables[1]
        assert isinstance(tab0, Table) and isinstance(tab1, Table)
        tab0.optimized_metadata = CacheMetadata(start_table_id=0, length=2, cached_tables=[tab0, tab1])
        tab0.update_prob_with_counts({"MyIngress.tab1_act": 60, "NoAction": 40})
        tab1.update_prob_with_counts({"MyIngress.tab2_act1": 60, "MyIngress.tab2_act2": 40})
        cache_table = tab0._create_cache_table(irg, ingress_graph, "cache_table")
        assert cache_table.name == "cache_table"
        cache_act_names = cache_table.action_names
        assert cache_act_names[0] == "merged_MyIngress.tab1_act_MyIngress.tab2_act1"
        assert cache_act_names[1] == "merged_MyIngress.tab1_act_MyIngress.tab2_act2"
        assert cache_act_names[2] == "merged_NoAction_MyIngress.tab2_act1"
        assert cache_act_names[3] == "merged_NoAction_MyIngress.tab2_act2"
        cache_keys = cache_table.keys
        assert len(cache_keys) == 17
        assert set([ckey.header for ckey in cache_keys]) == set(
            [
                "scalars.userMetadata.ccc",
                "ipv4.totalLen",
                "tcp.srcPort",
                "migration.tabl1_data",
                "scalars.userMetadata.aaa",
                "ipv4.srcAddr",
                "scalars.userMetadata.bbb",
                "ipv4.ttl",
                "ipv4.version",
                "ipv4.ihl",
                "ipv4.diffserv",
                "ipv4.identification",
                "ipv4.flags",
                "ipv4.fragOffset",
                "ipv4.protocol",
                "ipv4.hdrChecksum",
                "ipv4.dstAddr",
            ]
        )
        assert cache_table.default_action_name == "NoAction"
        assert cache_table._default_action_const == False
        assert cache_table._default_action_param == []
        assert cache_table._default_action_entry_const == False
        assert 0.35 > cache_table.action_to_probability[cache_act_names[0]] > 0.34
        assert 0.23 > cache_table.action_to_probability[cache_act_names[1]] > 0.22
        assert 0.23 > cache_table.action_to_probability[cache_act_names[2]] > 0.22
        assert 0.16 > cache_table.action_to_probability[cache_act_names[3]] > 0.15

    def test_cache_two_tables_rate_change(self, json_path):
        org_config = config.ENABLE_CACHE_HIT_RATE_CHANGE
        config.ENABLE_CACHE_HIT_RATE_CHANGE = True
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 3
        tab0 = tables[0]
        tab1 = tables[1]
        assert isinstance(tab0, Table) and isinstance(tab1, Table)
        tab0.optimized_metadata = CacheMetadata(start_table_id=0, length=2, cached_tables=[tab0, tab1])
        tab0.update_prob_with_counts({"MyIngress.tab1_act": 60, "NoAction": 40})
        tab1.update_prob_with_counts({"MyIngress.tab2_act1": 60, "MyIngress.tab2_act2": 40})
        cache_table = tab0._create_cache_table(irg, ingress_graph, "cache_table")
        assert cache_table.name == "cache_table"
        cache_act_names = cache_table.action_names
        assert cache_act_names[0] == "merged_MyIngress.tab1_act_MyIngress.tab2_act1"
        assert cache_act_names[1] == "merged_MyIngress.tab1_act_MyIngress.tab2_act2"
        assert cache_act_names[2] == "merged_NoAction_MyIngress.tab2_act1"
        assert cache_act_names[3] == "merged_NoAction_MyIngress.tab2_act2"
        cache_keys = cache_table.keys
        assert len(cache_keys) == 17
        assert set([ckey.header for ckey in cache_keys]) == set(
            [
                "scalars.userMetadata.ccc",
                "ipv4.totalLen",
                "tcp.srcPort",
                "migration.tabl1_data",
                "scalars.userMetadata.aaa",
                "ipv4.srcAddr",
                "scalars.userMetadata.bbb",
                "ipv4.ttl",
                "ipv4.version",
                "ipv4.ihl",
                "ipv4.diffserv",
                "ipv4.identification",
                "ipv4.flags",
                "ipv4.fragOffset",
                "ipv4.protocol",
                "ipv4.hdrChecksum",
                "ipv4.dstAddr",
            ]
        )
        assert cache_table.default_action_name == "NoAction"
        assert cache_table._default_action_const == False
        assert cache_table._default_action_param == []
        assert cache_table._default_action_entry_const == False
        assert math.isclose(
            cache_table.action_to_probability[cache_act_names[0]],
            0.6 * 0.6 * config.CACHE_HIT_RATE * config.CACHE_HIT_RATE,
            abs_tol=0.001,
        )
        assert math.isclose(
            cache_table.action_to_probability[cache_act_names[1]],
            0.6 * 0.4 * config.CACHE_HIT_RATE * config.CACHE_HIT_RATE,
            abs_tol=0.001,
        )
        assert math.isclose(
            cache_table.action_to_probability[cache_act_names[2]],
            0.6 * 0.4 * config.CACHE_HIT_RATE * config.CACHE_HIT_RATE,
            abs_tol=0.001,
        )
        assert math.isclose(
            cache_table.action_to_probability[cache_act_names[3]],
            0.4 * 0.4 * config.CACHE_HIT_RATE * config.CACHE_HIT_RATE,
            abs_tol=0.001,
        )
        print(cache_table.action_to_probability)
        assert math.isclose(
            cache_table.action_to_probability[cache_table.default_action_name],
            1 - config.CACHE_HIT_RATE * config.CACHE_HIT_RATE,
            abs_tol=0.001,
        )
        config.ENABLE_CACHE_HIT_RATE_CHANGE = org_config

    def test_cache_three_tables(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 3
        tab0 = tables[0]
        tab1 = tables[1]
        tab2 = tables[2]
        assert isinstance(tab0, Table) and isinstance(tab1, Table) and isinstance(tab2, Table)
        tab0.optimized_metadata = CacheMetadata(start_table_id=0, length=3, cached_tables=[tab0, tab1, tab2])
        tab0.update_prob_with_counts({"MyIngress.tab1_act": 60, "NoAction": 40})
        tab1.update_prob_with_counts({"MyIngress.tab2_act1": 60, "MyIngress.tab2_act2": 40})
        tab2.update_prob_with_counts({"MyIngress.tab3_act1": 50, "MyIngress.tab3_act2": 50})
        cache_table = tab0._create_cache_table(irg, ingress_graph, "cache_table")
        assert cache_table.name == "cache_table"
        cache_act_names = cache_table.action_names
        assert cache_act_names[0] == "merged_MyIngress.tab1_act_MyIngress.tab2_act1_MyIngress.tab3_act1"
        assert cache_act_names[1] == "merged_MyIngress.tab1_act_MyIngress.tab2_act1_MyIngress.tab3_act2"
        assert cache_act_names[2] == "merged_MyIngress.tab1_act_MyIngress.tab2_act2_MyIngress.tab3_act1"
        assert cache_act_names[3] == "merged_MyIngress.tab1_act_MyIngress.tab2_act2_MyIngress.tab3_act2"
        assert cache_act_names[4] == "merged_NoAction_MyIngress.tab2_act1_MyIngress.tab3_act1"
        assert cache_act_names[5] == "merged_NoAction_MyIngress.tab2_act1_MyIngress.tab3_act2"
        assert cache_act_names[6] == "merged_NoAction_MyIngress.tab2_act2_MyIngress.tab3_act1"
        assert cache_act_names[7] == "merged_NoAction_MyIngress.tab2_act2_MyIngress.tab3_act2"
        cache_keys = cache_table.keys
        assert len(cache_keys) == 20
        assert set([ckey.header for ckey in cache_keys]) == set(
            [
                "scalars.userMetadata.ccc",
                "ipv4.totalLen",
                "tcp.srcPort",
                "migration.tabl1_data",
                "scalars.userMetadata.aaa",
                "ipv4.srcAddr",
                "scalars.userMetadata.bbb",
                "ipv4.ttl",
                "ipv4.version",
                "ipv4.ihl",
                "ipv4.diffserv",
                "ipv4.identification",
                "ipv4.flags",
                "ipv4.fragOffset",
                "ipv4.protocol",
                "ipv4.hdrChecksum",
                "ipv4.dstAddr",
                "tcp.window",
                "ethernet.srcAddr",
                "standard_metadata.ingress_port",
            ]
        )
        assert set([ckey.name for ckey in cache_keys]) == set(
            [
                "meta.ccc",
                "hdr.ipv4.totalLen",
                "hdr.tcp.srcPort",
                "hdr.migration.tabl1_data",
                "meta.aaa",
                "hdr.ipv4.srcAddr",
                "meta.bbb",
                "hdr.ipv4.ttl",
                "hdr.ipv4.version",
                "hdr.ipv4.ihl",
                "hdr.ipv4.diffserv",
                "hdr.ipv4.identification",
                "hdr.ipv4.flags",
                "hdr.ipv4.fragOffset",
                "hdr.ipv4.protocol",
                "hdr.ipv4.hdrChecksum",
                "hdr.ipv4.dstAddr",
                "hdr.tcp.window",
                "hdr.ethernet.srcAddr",
                "standard_metadata.ingress_port",
            ]
        )
        assert cache_table.default_action_name == "NoAction"
        assert cache_table._default_action_const == False
        assert cache_table._default_action_param == []
        assert cache_table._default_action_entry_const == False
        assert 0.18 > cache_table.action_to_probability[cache_act_names[0]] > 0.17
        assert 0.18 > cache_table.action_to_probability[cache_act_names[1]] > 0.17
        assert 0.12 > cache_table.action_to_probability[cache_act_names[2]] > 0.11
        assert 0.12 > cache_table.action_to_probability[cache_act_names[3]] > 0.11
        assert 0.12 > cache_table.action_to_probability[cache_act_names[4]] > 0.11
        assert 0.12 > cache_table.action_to_probability[cache_act_names[5]] > 0.11
        assert 0.08 > cache_table.action_to_probability[cache_act_names[6]] > 0.07
        assert 0.08 > cache_table.action_to_probability[cache_act_names[7]] > 0.07

    def test_cache_three_tables_rate_change(self, json_path):
        org_config = config.ENABLE_CACHE_HIT_RATE_CHANGE
        config.ENABLE_CACHE_HIT_RATE_CHANGE = True
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 3
        tab0 = tables[0]
        tab1 = tables[1]
        tab2 = tables[2]
        assert isinstance(tab0, Table) and isinstance(tab1, Table) and isinstance(tab2, Table)
        tab0.optimized_metadata = CacheMetadata(start_table_id=0, length=3, cached_tables=[tab0, tab1, tab2])
        tab0.update_prob_with_counts({"MyIngress.tab1_act": 60, "NoAction": 40})
        tab1.update_prob_with_counts({"MyIngress.tab2_act1": 60, "MyIngress.tab2_act2": 40})
        tab2.update_prob_with_counts({"MyIngress.tab3_act1": 50, "MyIngress.tab3_act2": 50})
        cache_table = tab0._create_cache_table(irg, ingress_graph, "cache_table")
        assert cache_table.name == "cache_table"
        cache_act_names = cache_table.action_names
        assert cache_act_names[0] == "merged_MyIngress.tab1_act_MyIngress.tab2_act1_MyIngress.tab3_act1"
        assert cache_act_names[1] == "merged_MyIngress.tab1_act_MyIngress.tab2_act1_MyIngress.tab3_act2"
        assert cache_act_names[2] == "merged_MyIngress.tab1_act_MyIngress.tab2_act2_MyIngress.tab3_act1"
        assert cache_act_names[3] == "merged_MyIngress.tab1_act_MyIngress.tab2_act2_MyIngress.tab3_act2"
        assert cache_act_names[4] == "merged_NoAction_MyIngress.tab2_act1_MyIngress.tab3_act1"
        assert cache_act_names[5] == "merged_NoAction_MyIngress.tab2_act1_MyIngress.tab3_act2"
        assert cache_act_names[6] == "merged_NoAction_MyIngress.tab2_act2_MyIngress.tab3_act1"
        assert cache_act_names[7] == "merged_NoAction_MyIngress.tab2_act2_MyIngress.tab3_act2"
        cache_keys = cache_table.keys
        assert len(cache_keys) == 20
        assert set([ckey.header for ckey in cache_keys]) == set(
            [
                "scalars.userMetadata.ccc",
                "ipv4.totalLen",
                "tcp.srcPort",
                "migration.tabl1_data",
                "scalars.userMetadata.aaa",
                "ipv4.srcAddr",
                "scalars.userMetadata.bbb",
                "ipv4.ttl",
                "ipv4.version",
                "ipv4.ihl",
                "ipv4.diffserv",
                "ipv4.identification",
                "ipv4.flags",
                "ipv4.fragOffset",
                "ipv4.protocol",
                "ipv4.hdrChecksum",
                "ipv4.dstAddr",
                "tcp.window",
                "ethernet.srcAddr",
                "standard_metadata.ingress_port",
            ]
        )
        assert set([ckey.name for ckey in cache_keys]) == set(
            [
                "meta.ccc",
                "hdr.ipv4.totalLen",
                "hdr.tcp.srcPort",
                "hdr.migration.tabl1_data",
                "meta.aaa",
                "hdr.ipv4.srcAddr",
                "meta.bbb",
                "hdr.ipv4.ttl",
                "hdr.ipv4.version",
                "hdr.ipv4.ihl",
                "hdr.ipv4.diffserv",
                "hdr.ipv4.identification",
                "hdr.ipv4.flags",
                "hdr.ipv4.fragOffset",
                "hdr.ipv4.protocol",
                "hdr.ipv4.hdrChecksum",
                "hdr.ipv4.dstAddr",
                "hdr.tcp.window",
                "hdr.ethernet.srcAddr",
                "standard_metadata.ingress_port",
            ]
        )
        assert cache_table.default_action_name == "NoAction"
        assert cache_table._default_action_const == False
        assert cache_table._default_action_param == []
        assert cache_table._default_action_entry_const == False
        assert math.isclose(
            cache_table.action_to_probability[cache_act_names[0]],
            0.6 * 0.6 * 0.5 * (config.CACHE_HIT_RATE**3),
            abs_tol=0.001,
        )
        assert math.isclose(
            cache_table.action_to_probability[cache_act_names[2]],
            0.6 * 0.4 * 0.5 * (config.CACHE_HIT_RATE**3),
            abs_tol=0.001,
        )
        assert math.isclose(
            cache_table.action_to_probability[cache_table.default_action_name],
            1 - (config.CACHE_HIT_RATE**3),
            abs_tol=0.001,
        )
        config.ENABLE_CACHE_HIT_RATE_CHANGE = org_config


@pytest.mark.parametrize(
    "json_path",
    [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "pipelet_pipelet_group", "test.p4.json")],
)
class TestGroupCache:
    def test_group_cache_if_elseif_else(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tab_conds = ingress_graph.name_to_normal_node
        """
        if (hdr.tcp.srcPort == 100) {
            tab15.apply();
        } else if (hdr.tcp.srcPort == 120) {
            tab16.apply();
        } else {
            tab17.apply();
        }
        """
        node_26 = tab_conds["node_26"]
        node_28 = tab_conds["node_28"]
        tab15 = tab_conds["MyIngress.tab15"]
        tab16 = tab_conds["MyIngress.tab16"]
        tab17 = tab_conds["MyIngress.tab17"]
        assert isinstance(node_26, Condition) and isinstance(node_28, Condition)
        assert isinstance(tab15, Table) and isinstance(tab16, Table) and isinstance(tab17, Table)
        pipe_grp = PipeletGroup(
            irgraph_pipe=ingress_graph,
            root=node_26,
            sink=ingress_graph.sink,
            pipelets=[
                Pipelet(ingress_graph, tab15, 1),
                Pipelet(ingress_graph, tab16, 1),
                Pipelet(ingress_graph, tab17, 1),
            ],
        )
        tab15.optimized_metadata = GroupCacheMetadata(
            pipe_grp=pipe_grp, root=pipe_grp.root, sink=pipe_grp.sink, cached_tables=pipe_grp.nodes
        )
        node_26.true_probability = 0.5
        node_28.true_probability = 0.5
        tab15.update_prob_with_counts({"MyIngress.common_act": 60, "NoAction": 40})
        tab16.update_prob_with_counts({"MyIngress.common_act": 60, "NoAction": 40})
        tab17.update_prob_with_counts({"MyIngress.common_act": 60, "NoAction": 40})
        cache_table = tab15._create_group_cache_table(
            ir_graph=irg, irgraph_pipe=ingress_graph, cache_table_name="cache_table"
        )

        assert cache_table.name == "cache_table"
        assert len(cache_table.action_names) == 7
        cache_act_names = cache_table.action_names
        assert len(cache_table.keys) == 2
        assert cache_table.default_action_name == "NoAction"
        assert cache_table._default_action_const == False
        assert cache_table._default_action_param == []
        assert cache_table._default_action_entry_const == False
        assert 0.29 > cache_table.action_to_probability[cache_act_names[0]] > 0.28
        assert 0.20 > cache_table.action_to_probability[cache_act_names[1]] > 0.19
        assert 0.15 > cache_table.action_to_probability[cache_act_names[2]] > 0.14
        assert 0.10 > cache_table.action_to_probability[cache_act_names[3]] > 0.08
        assert 0.15 > cache_table.action_to_probability[cache_act_names[4]] > 0.14
        assert 0.10 > cache_table.action_to_probability[cache_act_names[5]] > 0.08
        assert 0.051 > cache_table.action_to_probability[cache_act_names[6]] > 0.049

    def test_group_cache_if_elseif_else_rate_change(self, json_path):
        org_config = config.ENABLE_CACHE_HIT_RATE_CHANGE
        config.ENABLE_CACHE_HIT_RATE_CHANGE = True
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tab_conds = ingress_graph.name_to_normal_node
        """
        if (hdr.tcp.srcPort == 100) {
            tab15.apply();
        } else if (hdr.tcp.srcPort == 120) {
            tab16.apply();
        } else {
            tab17.apply();
        }
        """
        node_26 = tab_conds["node_26"]
        node_28 = tab_conds["node_28"]
        tab15 = tab_conds["MyIngress.tab15"]
        tab16 = tab_conds["MyIngress.tab16"]
        tab17 = tab_conds["MyIngress.tab17"]
        assert isinstance(node_26, Condition) and isinstance(node_28, Condition)
        assert isinstance(tab15, Table) and isinstance(tab16, Table) and isinstance(tab17, Table)
        pipe_grp = PipeletGroup(
            irgraph_pipe=ingress_graph,
            root=node_26,
            sink=ingress_graph.sink,
            pipelets=[
                Pipelet(ingress_graph, tab15, 1),
                Pipelet(ingress_graph, tab16, 1),
                Pipelet(ingress_graph, tab17, 1),
            ],
        )
        tab15.optimized_metadata = GroupCacheMetadata(
            pipe_grp=pipe_grp, root=pipe_grp.root, sink=pipe_grp.sink, cached_tables=pipe_grp.nodes
        )
        node_26.true_probability = 0.5
        node_28.true_probability = 0.5
        tab15.update_prob_with_counts({"MyIngress.common_act": 60, "NoAction": 40})
        tab16.update_prob_with_counts({"MyIngress.common_act": 60, "NoAction": 40})
        tab17.update_prob_with_counts({"MyIngress.common_act": 60, "NoAction": 40})
        cache_table = tab15._create_group_cache_table(
            ir_graph=irg, irgraph_pipe=ingress_graph, cache_table_name="cache_table"
        )

        assert cache_table.name == "cache_table"
        assert len(cache_table.action_names) == 7
        cache_act_names = cache_table.action_names
        assert len(cache_table.keys) == 2
        assert cache_table.default_action_name == "NoAction"
        assert cache_table._default_action_const == False
        assert cache_table._default_action_param == []
        assert cache_table._default_action_entry_const == False
        assert math.isclose(
            cache_table.action_to_probability[cache_act_names[0]],
            0.5 * 0.6 * (config.CACHE_HIT_RATE**5),
            abs_tol=0.001,
        )
        assert math.isclose(
            cache_table.action_to_probability[cache_act_names[1]],
            0.5 * 0.4 * (config.CACHE_HIT_RATE**5),
            abs_tol=0.001,
        )
        assert math.isclose(
            cache_table.action_to_probability[cache_table.default_action_name],
            1 - (config.CACHE_HIT_RATE**5),
            abs_tol=0.001,
        )
        config.ENABLE_CACHE_HIT_RATE_CHANGE = org_config

    def test_group_cache_single_if(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tab_conds = ingress_graph.name_to_normal_node
        """
        if (hdr.tcp.srcPort == 80) {
            tab06.apply();
        }
        """
        node_9 = tab_conds["node_9"]
        tab06 = tab_conds["MyIngress.tab06"]
        tab08 = tab_conds["MyIngress.tab08"]
        assert isinstance(node_9, Condition)
        assert isinstance(tab06, Table) and isinstance(tab08, Table)
        pipe_grp = PipeletGroup(
            irgraph_pipe=ingress_graph, root=node_9, sink=tab08, pipelets=[Pipelet(ingress_graph, tab06, 1)]
        )
        tab06.optimized_metadata = GroupCacheMetadata(
            pipe_grp=pipe_grp, root=pipe_grp.root, sink=pipe_grp.sink, cached_tables=pipe_grp.nodes
        )
        node_9.true_probability = 0.5
        tab06.update_prob_with_counts({"MyIngress.common_act": 60, "NoAction": 40})
        cache_table = tab06._create_group_cache_table(
            ir_graph=irg, irgraph_pipe=ingress_graph, cache_table_name="cache_table"
        )

        assert cache_table.name == "cache_table"
        assert len(cache_table.action_names) == 3
        cache_act_names = cache_table.action_names
        assert len(cache_table.keys) == 2
        assert cache_table.default_action_name == "NoAction"
        assert cache_table._default_action_const == False
        assert cache_table._default_action_param == []
        assert cache_table._default_action_entry_const == False
        assert 0.58 > cache_table.action_to_probability[cache_act_names[0]] > 0.57
        assert 0.39 > cache_table.action_to_probability[cache_act_names[1]] > 0.38
        assert 0.051 > cache_table.action_to_probability[cache_act_names[2]] > 0.049

    def test_group_cache_table_single_if(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tab_conds = ingress_graph.name_to_normal_node
        """
        tab07.apply();
        if (hdr.tcp.srcPort == 80) {
            tab18.apply();
            tab19.apply();
        }
        """
        tab07 = tab_conds["MyIngress.tab07"]
        node_12 = tab_conds["node_12"]
        tab18 = tab_conds["MyIngress.tab18"]
        tab19 = tab_conds["MyIngress.tab19"]
        tab20 = tab_conds["MyIngress.tab20"]
        assert isinstance(node_12, Condition)
        assert (
            isinstance(tab07, Table)
            and isinstance(tab18, Table)
            and isinstance(tab19, Table)
            and isinstance(tab20, Table)
        )
        pipe_grp = PipeletGroup(
            irgraph_pipe=ingress_graph,
            root=tab07,
            sink=tab20,
            pipelets=[Pipelet(ingress_graph, tab07, 1), Pipelet(ingress_graph, tab18, 2)],
        )
        tab07.optimized_metadata = GroupCacheMetadata(
            pipe_grp=pipe_grp, root=pipe_grp.root, sink=pipe_grp.sink, cached_tables=pipe_grp.nodes
        )
        node_12.true_probability = 0.5
        tab07.update_prob_with_counts({"MyIngress.common_act": 60, "NoAction": 40})
        tab18.update_prob_with_counts({"MyIngress.common_act": 60, "NoAction": 40})
        tab19.update_prob_with_counts({"MyIngress.common_act": 60, "NoAction": 40})
        cache_table = tab07._create_group_cache_table(
            ir_graph=irg, irgraph_pipe=ingress_graph, cache_table_name="cache_table"
        )

        assert cache_table.name == "cache_table"
        assert len(cache_table.action_names) == 9
        cache_act_names = cache_table.action_names
        assert len(cache_table.keys) == 2
        assert cache_table.default_action_name == "NoAction"
        assert cache_table._default_action_const == False
        assert cache_table._default_action_param == []
        assert cache_table._default_action_entry_const == False
        assert 0.21 > cache_table.action_to_probability[cache_act_names[0]] > 0.20
        assert 0.14 > cache_table.action_to_probability[cache_act_names[1]] > 0.13
        assert 0.14 > cache_table.action_to_probability[cache_act_names[2]] > 0.13
        assert 0.10 > cache_table.action_to_probability[cache_act_names[3]] > 0.09
        assert 0.14 > cache_table.action_to_probability[cache_act_names[4]] > 0.13
        assert 0.10 > cache_table.action_to_probability[cache_act_names[5]] > 0.09
        assert 0.10 > cache_table.action_to_probability[cache_act_names[6]] > 0.09
        assert 0.07 > cache_table.action_to_probability[cache_act_names[7]] > 0.06
        assert 0.051 > cache_table.action_to_probability[cache_act_names[8]] > 0.049

    def test_group_cache_single_if_table(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tab_conds = ingress_graph.name_to_normal_node
        """
        if (hdr.tcp.srcPort == 80) {
            tab18.apply();
            tab19.apply();
        }
        tab20.apply();
        """
        node_12 = tab_conds["node_12"]
        tab18 = tab_conds["MyIngress.tab18"]
        tab19 = tab_conds["MyIngress.tab19"]
        tab20 = tab_conds["MyIngress.tab20"]
        tab08 = tab_conds["MyIngress.tab08"]
        assert isinstance(node_12, Condition)
        assert (
            isinstance(tab08, Table)
            and isinstance(tab18, Table)
            and isinstance(tab19, Table)
            and isinstance(tab20, Table)
        )
        pipe_grp = PipeletGroup(
            irgraph_pipe=ingress_graph,
            root=node_12,
            sink=tab08,
            pipelets=[Pipelet(ingress_graph, tab18, 2), Pipelet(ingress_graph, tab20, 1)],
        )
        tab18.optimized_metadata = GroupCacheMetadata(
            pipe_grp=pipe_grp, root=pipe_grp.root, sink=pipe_grp.sink, cached_tables=pipe_grp.nodes
        )
        node_12.true_probability = 0.5
        tab18.update_prob_with_counts({"MyIngress.common_act": 60, "NoAction": 40})
        tab19.update_prob_with_counts({"MyIngress.common_act": 60, "NoAction": 40})
        tab20.update_prob_with_counts({"MyIngress.common_act": 60, "NoAction": 40})
        cache_table = tab18._create_group_cache_table(
            ir_graph=irg, irgraph_pipe=ingress_graph, cache_table_name="cache_table"
        )

        assert cache_table.name == "cache_table"
        assert len(cache_table.action_names) == 11
        cache_act_names = cache_table.action_names
        assert len(cache_table.keys) == 2
        assert cache_table.default_action_name == "NoAction"
        assert cache_table._default_action_const == False
        assert cache_table._default_action_param == []
        assert cache_table._default_action_entry_const == False
        assert 0.11 > cache_table.action_to_probability[cache_act_names[0]] > 0.10
        assert 0.07 > cache_table.action_to_probability[cache_act_names[1]] > 0.06
        assert 0.07 > cache_table.action_to_probability[cache_act_names[2]] > 0.06
        assert 0.05 > cache_table.action_to_probability[cache_act_names[3]] > 0.04
        assert 0.07 > cache_table.action_to_probability[cache_act_names[4]] > 0.06
        assert 0.05 > cache_table.action_to_probability[cache_act_names[5]] > 0.04
        assert 0.05 > cache_table.action_to_probability[cache_act_names[6]] > 0.04
        assert 0.04 > cache_table.action_to_probability[cache_act_names[7]] > 0.03
        assert 0.29 > cache_table.action_to_probability[cache_act_names[8]] > 0.28
        assert 0.20 > cache_table.action_to_probability[cache_act_names[9]] > 0.19
        assert 0.051 > cache_table.action_to_probability[cache_act_names[10]] > 0.049

    def test_group_cache_switch(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tab_conds = ingress_graph.name_to_normal_node
        """
        switch (tab_switch.apply().action_run) {
            common_act: {
                tab11.apply();
                tab12.apply();
            }
            increment_ttl: {
                tab13.apply();
            }
            decrement_ttl: {
                tab21.apply();
            }
        }
        """
        node_24 = tab_conds["node_24"]
        tab_switch = tab_conds["MyIngress.tab_switch"]
        tab11 = tab_conds["MyIngress.tab11"]
        tab12 = tab_conds["MyIngress.tab12"]
        tab13 = tab_conds["MyIngress.tab13"]
        tab21 = tab_conds["MyIngress.tab21"]
        assert isinstance(node_24, Condition)
        assert (
            isinstance(tab11, Table)
            and isinstance(tab12, Table)
            and isinstance(tab13, Table)
            and isinstance(tab21, Table)
            and isinstance(tab_switch, Table)
        )
        pipe_grp = PipeletGroup(
            irgraph_pipe=ingress_graph,
            root=tab_switch,
            sink=node_24,
            pipelets=[
                Pipelet(ingress_graph, tab_switch, 1),
                Pipelet(ingress_graph, tab11, 2),
                Pipelet(ingress_graph, tab13, 1),
                Pipelet(ingress_graph, tab21, 1),
            ],
        )
        tab_switch.optimized_metadata = GroupCacheMetadata(
            pipe_grp=pipe_grp, root=pipe_grp.root, sink=pipe_grp.sink, cached_tables=pipe_grp.nodes
        )
        tab_switch.update_prob_with_counts(
            {"MyIngress.common_act": 25, "MyIngress.decrement_ttl": 25, "MyIngress.increment_ttl": 25, "NoAction": 25}
        )
        tab11.update_prob_with_counts({"MyIngress.common_act": 60, "NoAction": 40})
        tab12.update_prob_with_counts({"MyIngress.common_act": 60, "NoAction": 40})
        tab13.update_prob_with_counts({"MyIngress.common_act": 60, "NoAction": 40})
        tab21.update_prob_with_counts({"MyIngress.common_act": 60, "NoAction": 40})
        cache_table = tab_switch._create_group_cache_table(
            ir_graph=irg, irgraph_pipe=ingress_graph, cache_table_name="cache_table"
        )

        assert cache_table.name == "cache_table"
        assert len(cache_table.action_names) == 10
        cache_act_names = cache_table.action_names
        assert len(cache_table.keys) == 2
        assert cache_table.default_action_name == "NoAction"
        assert cache_table._default_action_const == False
        assert cache_table._default_action_param == []
        assert cache_table._default_action_entry_const == False
        assert 0.09 > cache_table.action_to_probability[cache_act_names[0]] > 0.08
        assert 0.06 > cache_table.action_to_probability[cache_act_names[1]] > 0.05
        assert 0.06 > cache_table.action_to_probability[cache_act_names[2]] > 0.05
        assert 0.04 > cache_table.action_to_probability[cache_act_names[3]] > 0.03
        assert 0.15 > cache_table.action_to_probability[cache_act_names[4]] > 0.14
        assert 0.10 > cache_table.action_to_probability[cache_act_names[5]] > 0.09
        assert 0.15 > cache_table.action_to_probability[cache_act_names[6]] > 0.14
        assert 0.10 > cache_table.action_to_probability[cache_act_names[7]] > 0.09
        assert 0.24 > cache_table.action_to_probability[cache_act_names[8]] > 0.23
        assert 0.051 > cache_table.action_to_probability[cache_act_names[9]] > 0.049
