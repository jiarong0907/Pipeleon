import os
from typing import List
from graph_optimizer.json_manager import JsonManager
from ir.match_key import MatchKey, MatchType
from ir.table_entry import (
    EntryMatchKeyParam,
    ExactEntryMatchKeyParam,
    LpmEntryMatchKeyParam,
    TableEntry,
    TernaryEntryMatchKeyParam,
)
from ir.table_entry_builder import MergeTableEntryBuilder
import pytest
import mock_import
from unittest.mock import Mock, patch

import utils


@pytest.mark.parametrize(
    "json_path", [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "merge", "test.p4.json")]
)
class TestMergeEntryBuilder:
    def test_get_exact_key_mask(self, json_path):
        # The P4 program here does not matter, just used it to create
        # the header and header type list
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 2
        merge_builder = MergeTableEntryBuilder(irg, tables[0], tables[1])

        assert merge_builder._get_exact_key_mask("1") == "f"
        assert merge_builder._get_exact_key_mask("f") == "f"
        assert merge_builder._get_exact_key_mask("0") == "f"
        assert merge_builder._get_exact_key_mask("0000") == "ffff"
        assert merge_builder._get_exact_key_mask("abcd") == "ffff"
        assert merge_builder._get_exact_key_mask("0123") == "ffff"

    def test_get_lpm_key_mask(self, json_path):
        # The P4 program here does not matter, just used it to create
        # the header and header type list
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 2
        merge_builder = MergeTableEntryBuilder(irg, tables[0], tables[1])

        prefix_length_to_mask = {
            1: "80000000",
            2: "c0000000",
            3: "e0000000",
            4: "f0000000",
            32: "ffffffff",
        }
        for k, v in prefix_length_to_mask.items():
            assert (
                merge_builder._get_lpm_key_mask(
                    table_match_key=MatchKey("ipv4.srcAddr", MatchType.LPM, None, "hdr.ipv4.srcAddr"), prefix_length=k
                )
                == v
            )

        prefix_length_to_mask2 = {
            1: "20",
            2: "30",
            3: "38",
            4: "3c",
            5: "3e",
            6: "3f",
        }
        # tcp.ctrl is 6-bit long
        # TODO: The current implementation assumes key length is x times of 4 bits.
        # for k,v in prefix_length_to_mask2.items():
        #     assert merge_builder._get_lpm_key_mask(
        #         table_match_key=MatchKey("tcp.ctrl", MatchType.LPM, None, "tcp.ctrl"),
        #         prefix_length=k
        #     ) == v

    def test_convert_all_entry_keys_to_ternary(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 6
        tab_mix = tables[5]
        tab_any = tables[4]
        merge_builder = MergeTableEntryBuilder(irg, tab_mix, tab_any)

        entries: List[TableEntry] = []
        match_keys: List[EntryMatchKeyParam] = []
        match_keys.append(ExactEntryMatchKeyParam(type="EXACT", key="0a01"))
        match_keys.append(LpmEntryMatchKeyParam(type="LPM", key="0a230a01", prefix_length=3))
        match_keys.append(TernaryEntryMatchKeyParam(type="TERNARY", key="0a000a01", mask="ff000ff0"))
        match_keys.append(TernaryEntryMatchKeyParam(type="TERNARY", key="0a000a01", mask="ffff0230"))

        entries.append(TableEntry(action_name="test", action_data=[], match_key=match_keys, priority=5))

        converted_entries = merge_builder._convert_all_entry_keys_to_ternary(tab_mix, entries)
        assert len(converted_entries) == 1
        entry = converted_entries[0]
        assert entry.action_name == entries[0].action_name
        assert entry.action_data == entries[0].action_data
        assert entry.priority == 5
        for mkey in entry.match_key:
            assert isinstance(mkey, TernaryEntryMatchKeyParam)
            assert mkey.type == "TERNARY"

        assert len(entry.match_key) == 4
        assert entry.match_key[0].key == "0a01" and entry.match_key[0].mask == "ffff"
        assert entry.match_key[1].key == "0a230a01" and entry.match_key[1].mask == "e0000000"
        assert entry.match_key[2].key == "0a000a01" and entry.match_key[2].mask == "ff000ff0"
        assert entry.match_key[3].key == "0a000a01" and entry.match_key[3].mask == "ffff0230"

    def test_merge_exact_exact(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 2
        exact_tab1 = tables[0]
        exact_tab2 = tables[1]
        merge_builder = MergeTableEntryBuilder(irg, exact_tab1, exact_tab2)

        group1: List[TableEntry] = []
        match_keys11: List[EntryMatchKeyParam] = []
        match_keys11.append(ExactEntryMatchKeyParam(type="EXACT", key="0a01"))
        match_keys11.append(ExactEntryMatchKeyParam(type="EXACT", key="0a010000"))
        group1.append(
            TableEntry(
                action_name="MyIngress.tab_exact1_act1", action_data=["ff010000"], match_key=match_keys11, priority=-1
            )
        )
        match_keys12: List[EntryMatchKeyParam] = []
        match_keys12.append(ExactEntryMatchKeyParam(type="EXACT", key="fa01"))
        match_keys12.append(ExactEntryMatchKeyParam(type="EXACT", key="fa010000"))
        group1.append(
            TableEntry(action_name="MyIngress.tab_exact1_act2", action_data=[], match_key=match_keys12, priority=-1)
        )

        group2: List[TableEntry] = []
        match_keys21: List[EntryMatchKeyParam] = []
        match_keys21.append(ExactEntryMatchKeyParam(type="EXACT", key="ca01"))
        match_keys21.append(ExactEntryMatchKeyParam(type="EXACT", key="ca010000"))
        group2.append(
            TableEntry(
                action_name="MyIngress.tab_exact2_act1", action_data=["ff01000a"], match_key=match_keys21, priority=-1
            )
        )
        match_keys22: List[EntryMatchKeyParam] = []
        match_keys22.append(ExactEntryMatchKeyParam(type="EXACT", key="cc01"))
        match_keys22.append(ExactEntryMatchKeyParam(type="EXACT", key="cc010000"))
        group2.append(
            TableEntry(action_name="MyIngress.tab_exact2_act2", action_data=[], match_key=match_keys22, priority=-1)
        )

        converted_entries = merge_builder._cross_product_entries(MatchType.LPM, group1, group2)
        assert len(converted_entries) == 4
        entry0 = converted_entries[0]
        entry1 = converted_entries[1]
        entry2 = converted_entries[2]
        entry3 = converted_entries[3]
        assert entry0.action_name == "merged_MyIngress.tab_exact1_act1_MyIngress.tab_exact2_act1"
        assert entry1.action_name == "merged_MyIngress.tab_exact1_act1_MyIngress.tab_exact2_act2"
        assert entry2.action_name == "merged_MyIngress.tab_exact1_act2_MyIngress.tab_exact2_act1"
        assert entry3.action_name == "merged_MyIngress.tab_exact1_act2_MyIngress.tab_exact2_act2"

        assert entry0.action_data == ["ff010000", "ff01000a"]
        assert entry1.action_data == ["ff010000"]
        assert entry2.action_data == ["ff01000a"]
        assert entry3.action_data == []

        for entry in converted_entries:
            assert entry.priority == -1

        assert [k._p4cir2json() for k in entry0.match_key] == [
            {"type": "EXACT", "key": "0a01"},
            {"type": "EXACT", "key": "0a010000"},
            {"type": "EXACT", "key": "ca01"},
            {"type": "EXACT", "key": "ca010000"},
        ]
        assert [k._p4cir2json() for k in entry1.match_key] == [
            {"type": "EXACT", "key": "0a01"},
            {"type": "EXACT", "key": "0a010000"},
            {"type": "EXACT", "key": "cc01"},
            {"type": "EXACT", "key": "cc010000"},
        ]
        assert [k._p4cir2json() for k in entry2.match_key] == [
            {"type": "EXACT", "key": "fa01"},
            {"type": "EXACT", "key": "fa010000"},
            {"type": "EXACT", "key": "ca01"},
            {"type": "EXACT", "key": "ca010000"},
        ]
        assert [k._p4cir2json() for k in entry3.match_key] == [
            {"type": "EXACT", "key": "fa01"},
            {"type": "EXACT", "key": "fa010000"},
            {"type": "EXACT", "key": "cc01"},
            {"type": "EXACT", "key": "cc010000"},
        ]

    def test_merge_exact_lpm(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 3
        exact_tab1 = tables[0]
        lpm_tab2 = tables[2]
        merge_builder = MergeTableEntryBuilder(irg, exact_tab1, lpm_tab2)

        group1: List[TableEntry] = []
        match_keys11: List[EntryMatchKeyParam] = []
        match_keys11.append(ExactEntryMatchKeyParam(type="EXACT", key="0a01"))
        match_keys11.append(ExactEntryMatchKeyParam(type="EXACT", key="0a010000"))
        group1.append(
            TableEntry(
                action_name="MyIngress.tab_exact1_act1", action_data=["ff010000"], match_key=match_keys11, priority=-1
            )
        )
        match_keys12: List[EntryMatchKeyParam] = []
        match_keys12.append(ExactEntryMatchKeyParam(type="EXACT", key="fa01"))
        match_keys12.append(ExactEntryMatchKeyParam(type="EXACT", key="fa010000"))
        group1.append(
            TableEntry(action_name="MyIngress.tab_exact1_act2", action_data=[], match_key=match_keys12, priority=-1)
        )

        group2: List[TableEntry] = []
        match_keys21: List[EntryMatchKeyParam] = []
        match_keys21.append(LpmEntryMatchKeyParam(type="LPM", key="ca010000", prefix_length=16))
        group2.append(
            TableEntry(
                action_name="MyIngress.tab_lpm1_act1", action_data=["ff01000a"], match_key=match_keys21, priority=-1
            )
        )
        match_keys22: List[EntryMatchKeyParam] = []
        match_keys22.append(LpmEntryMatchKeyParam(type="LPM", key="cc010000", prefix_length=8))
        group2.append(
            TableEntry(action_name="MyIngress.tab_lpm1_act2", action_data=[], match_key=match_keys22, priority=-1)
        )

        converted_entries = merge_builder._cross_product_entries(MatchType.LPM, group1, group2)
        assert len(converted_entries) == 4
        entry0 = converted_entries[0]
        entry1 = converted_entries[1]
        entry2 = converted_entries[2]
        entry3 = converted_entries[3]
        assert entry0.action_name == "merged_MyIngress.tab_exact1_act1_MyIngress.tab_lpm1_act1"
        assert entry1.action_name == "merged_MyIngress.tab_exact1_act1_MyIngress.tab_lpm1_act2"
        assert entry2.action_name == "merged_MyIngress.tab_exact1_act2_MyIngress.tab_lpm1_act1"
        assert entry3.action_name == "merged_MyIngress.tab_exact1_act2_MyIngress.tab_lpm1_act2"

        assert entry0.action_data == ["ff010000", "ff01000a"]
        assert entry1.action_data == ["ff010000"]
        assert entry2.action_data == ["ff01000a"]
        assert entry3.action_data == []

        for entry in converted_entries:
            assert entry.priority == -1

        assert [k._p4cir2json() for k in entry0.match_key] == [
            {"type": "EXACT", "key": "0a01"},
            {"type": "EXACT", "key": "0a010000"},
            {"type": "LPM", "key": "ca010000", "prefix_length": 16},
        ]
        assert [k._p4cir2json() for k in entry1.match_key] == [
            {"type": "EXACT", "key": "0a01"},
            {"type": "EXACT", "key": "0a010000"},
            {"type": "LPM", "key": "cc010000", "prefix_length": 8},
        ]
        assert [k._p4cir2json() for k in entry2.match_key] == [
            {"type": "EXACT", "key": "fa01"},
            {"type": "EXACT", "key": "fa010000"},
            {"type": "LPM", "key": "ca010000", "prefix_length": 16},
        ]
        assert [k._p4cir2json() for k in entry3.match_key] == [
            {"type": "EXACT", "key": "fa01"},
            {"type": "EXACT", "key": "fa010000"},
            {"type": "LPM", "key": "cc010000", "prefix_length": 8},
        ]

    def test_add_default_ternary(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 4
        exact_tab1 = tables[0]
        lpm_tab1 = tables[2]
        ternary_tab1 = tables[3]
        merge_builder = MergeTableEntryBuilder(irg, exact_tab1, lpm_tab1)

        # Test exact
        group1: List[TableEntry] = []
        match_keys11: List[EntryMatchKeyParam] = []
        match_keys11.append(ExactEntryMatchKeyParam(type="EXACT", key="0a01"))
        match_keys11.append(ExactEntryMatchKeyParam(type="EXACT", key="0a010000"))
        group1.append(
            TableEntry(
                action_name="MyIngress.tab_exact1_act1", action_data=["ff010000"], match_key=match_keys11, priority=-1
            )
        )
        match_keys12: List[EntryMatchKeyParam] = []
        match_keys12.append(ExactEntryMatchKeyParam(type="EXACT", key="fa01"))
        match_keys12.append(ExactEntryMatchKeyParam(type="EXACT", key="fa010000"))
        group1.append(
            TableEntry(action_name="MyIngress.tab_exact1_act2", action_data=[], match_key=match_keys12, priority=-1)
        )

        group1 = merge_builder._convert_all_entry_keys_to_ternary(exact_tab1, group1)
        exact_entries = merge_builder._add_default_ternary_entry(exact_tab1, group1)
        assert len(exact_entries) == 3
        entry0 = exact_entries[0]
        entry1 = exact_entries[1]
        entry2 = exact_entries[2]
        assert entry0.action_name == "MyIngress.tab_exact1_act1"
        assert entry1.action_name == "MyIngress.tab_exact1_act2"
        assert entry2.action_name == "MyIngress.tab_exact1_act2"
        assert entry0.action_data == ["ff010000"]
        assert entry1.action_data == []
        assert entry2.action_data == []
        assert entry0.priority == 2
        assert entry1.priority == 2
        assert entry2.priority == 1

        assert [k._p4cir2json() for k in entry0.match_key] == [
            {"type": "TERNARY", "key": "0a01", "mask": "ffff"},
            {"type": "TERNARY", "key": "0a010000", "mask": "ffffffff"},
        ]
        assert [k._p4cir2json() for k in entry1.match_key] == [
            {"type": "TERNARY", "key": "fa01", "mask": "ffff"},
            {"type": "TERNARY", "key": "fa010000", "mask": "ffffffff"},
        ]
        assert [k._p4cir2json() for k in entry2.match_key] == [
            {"type": "TERNARY", "key": "0000", "mask": "0000"},
            {"type": "TERNARY", "key": "00000000", "mask": "00000000"},
        ]

        # Test LPM
        group2: List[TableEntry] = []
        match_keys21: List[EntryMatchKeyParam] = []
        match_keys21.append(LpmEntryMatchKeyParam(type="LPM", key="ca010000", prefix_length=16))
        group2.append(
            TableEntry(
                action_name="MyIngress.tab_lpm1_act1", action_data=["ff01000a"], match_key=match_keys21, priority=-1
            )
        )
        match_keys22: List[EntryMatchKeyParam] = []
        match_keys22.append(LpmEntryMatchKeyParam(type="LPM", key="cc010000", prefix_length=8))
        group2.append(
            TableEntry(action_name="MyIngress.tab_lpm1_act2", action_data=[], match_key=match_keys22, priority=-1)
        )
        group2 = merge_builder._convert_all_entry_keys_to_ternary(lpm_tab1, group2)
        lpm_entries = merge_builder._add_default_ternary_entry(lpm_tab1, group2)
        assert len(lpm_entries) == 3
        entry0 = lpm_entries[0]
        entry1 = lpm_entries[1]
        entry2 = lpm_entries[2]
        assert entry0.action_name == "MyIngress.tab_lpm1_act1"
        assert entry1.action_name == "MyIngress.tab_lpm1_act2"
        assert entry2.action_name == "NoAction"
        assert entry0.action_data == ["ff01000a"]
        assert entry1.action_data == []
        assert entry2.action_data == []
        assert entry0.priority == 2
        assert entry1.priority == 2
        assert entry2.priority == 1

        assert [k._p4cir2json() for k in entry0.match_key] == [
            {"type": "TERNARY", "key": "ca010000", "mask": "ffff0000"}
        ]
        assert [k._p4cir2json() for k in entry1.match_key] == [
            {"type": "TERNARY", "key": "cc010000", "mask": "ff000000"}
        ]
        assert [k._p4cir2json() for k in entry2.match_key] == [
            {"type": "TERNARY", "key": "00000000", "mask": "00000000"}
        ]

        # Test ternary
        group3: List[TableEntry] = []
        match_keys31: List[EntryMatchKeyParam] = []
        match_keys31.append(TernaryEntryMatchKeyParam(type="TERNARY", key="cf010000", mask="ff000000"))
        group3.append(
            TableEntry(
                action_name="MyIngress.tab_ternary1_act1", action_data=["ff01bb0a"], match_key=match_keys31, priority=5
            )
        )
        match_keys32: List[EntryMatchKeyParam] = []
        match_keys32.append(TernaryEntryMatchKeyParam(type="TERNARY", key="cf010000", mask="ffff000f"))
        group3.append(
            TableEntry(action_name="MyIngress.tab_ternary1_act2", action_data=[], match_key=match_keys32, priority=3)
        )
        group3 = merge_builder._convert_all_entry_keys_to_ternary(ternary_tab1, group3)
        ternary_entries = merge_builder._add_default_ternary_entry(ternary_tab1, group3)
        assert len(ternary_entries) == 3
        entry0 = ternary_entries[0]
        entry1 = ternary_entries[1]
        entry2 = ternary_entries[2]
        assert entry0.action_name == "MyIngress.tab_ternary1_act1"
        assert entry1.action_name == "MyIngress.tab_ternary1_act2"
        assert entry2.action_name == "NoAction"
        assert entry0.action_data == ["ff01bb0a"]
        assert entry1.action_data == []
        assert entry2.action_data == []
        assert entry0.priority == 5
        assert entry1.priority == 3
        assert entry2.priority == 1

        assert [k._p4cir2json() for k in entry0.match_key] == [
            {"type": "TERNARY", "key": "cf010000", "mask": "ff000000"}
        ]
        assert [k._p4cir2json() for k in entry1.match_key] == [
            {"type": "TERNARY", "key": "cf010000", "mask": "ffff000f"}
        ]
        assert [k._p4cir2json() for k in entry2.match_key] == [
            {"type": "TERNARY", "key": "00000000", "mask": "00000000"}
        ]

    def test_merge_ternary_entries(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 5
        ternary_tab1 = tables[3]
        ternary_tab2 = tables[4]
        merge_builder = MergeTableEntryBuilder(irg, ternary_tab1, ternary_tab2)

        group1: List[TableEntry] = []
        match_keys11: List[EntryMatchKeyParam] = []
        match_keys11.append(TernaryEntryMatchKeyParam(type="TERNARY", key="cf010000", mask="ff000000"))
        group1.append(
            TableEntry(
                action_name="MyIngress.tab_ternary1_act1", action_data=["ff01bb0a"], match_key=match_keys11, priority=5
            )
        )
        match_keys12: List[EntryMatchKeyParam] = []
        match_keys12.append(TernaryEntryMatchKeyParam(type="TERNARY", key="cf010000", mask="ffff000f"))
        group1.append(
            TableEntry(action_name="MyIngress.tab_ternary1_act2", action_data=[], match_key=match_keys12, priority=3)
        )

        group2: List[TableEntry] = []
        match_keys21: List[EntryMatchKeyParam] = []
        match_keys21.append(TernaryEntryMatchKeyParam(type="TERNARY", key="bf010000", mask="fff00000"))
        group2.append(
            TableEntry(
                action_name="MyIngress.tab_ternary2_act1", action_data=["bf01bb0a"], match_key=match_keys21, priority=5
            )
        )
        match_keys22: List[EntryMatchKeyParam] = []
        match_keys22.append(TernaryEntryMatchKeyParam(type="TERNARY", key="bf010000", mask="fffff00f"))
        group2.append(
            TableEntry(action_name="MyIngress.tab_ternary2_act2", action_data=[], match_key=match_keys22, priority=3)
        )

        merged_entries = merge_builder._cross_product_entries(MatchType.TERNARY, group1, group2)
        assert len(merged_entries) == 4
        entry0 = merged_entries[0]
        entry1 = merged_entries[1]
        entry2 = merged_entries[2]
        entry3 = merged_entries[3]
        assert entry0.action_name == "merged_MyIngress.tab_ternary1_act1_MyIngress.tab_ternary2_act1"
        assert entry1.action_name == "merged_MyIngress.tab_ternary1_act1_MyIngress.tab_ternary2_act2"
        assert entry2.action_name == "merged_MyIngress.tab_ternary1_act2_MyIngress.tab_ternary2_act1"
        assert entry3.action_name == "merged_MyIngress.tab_ternary1_act2_MyIngress.tab_ternary2_act2"
        assert entry0.action_data == ["ff01bb0a", "bf01bb0a"]
        assert entry1.action_data == ["ff01bb0a"]
        assert entry2.action_data == ["bf01bb0a"]
        assert entry3.action_data == []
        assert entry0.priority == 10
        assert entry1.priority == 8
        assert entry2.priority == 8
        assert entry3.priority == 6

        assert [k._p4cir2json() for k in entry0.match_key] == [
            {"type": "TERNARY", "key": "cf010000", "mask": "ff000000"},
            {"type": "TERNARY", "key": "bf010000", "mask": "fff00000"},
        ]
        assert [k._p4cir2json() for k in entry1.match_key] == [
            {"type": "TERNARY", "key": "cf010000", "mask": "ff000000"},
            {"type": "TERNARY", "key": "bf010000", "mask": "fffff00f"},
        ]
        assert [k._p4cir2json() for k in entry2.match_key] == [
            {"type": "TERNARY", "key": "cf010000", "mask": "ffff000f"},
            {"type": "TERNARY", "key": "bf010000", "mask": "fff00000"},
        ]
        assert [k._p4cir2json() for k in entry3.match_key] == [
            {"type": "TERNARY", "key": "cf010000", "mask": "ffff000f"},
            {"type": "TERNARY", "key": "bf010000", "mask": "fffff00f"},
        ]

    @patch("ir.table_entry_builder.MergeTableEntryBuilder._cross_product_entries")
    def test_merge_two_tables_entries_exact_exact(self, _cross_product_entries, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 2
        exact_tab1 = tables[0]
        exact_tab2 = tables[1]
        merge_builder = MergeTableEntryBuilder(irg, exact_tab1, exact_tab2)
        merge_builder._merge_two_tables_entries(exact_tab1, exact_tab2)
        assert _cross_product_entries.call_count == 1

    @patch("ir.table_entry_builder.MergeTableEntryBuilder._cross_product_entries")
    def test_merge_two_tables_entries_exact_lpm(self, _cross_product_entries, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 3
        exact_tab1 = tables[0]
        lpm_tab1 = tables[2]
        merge_builder = MergeTableEntryBuilder(irg, exact_tab1, lpm_tab1)
        merge_builder._merge_two_tables_entries(exact_tab1, lpm_tab1)
        assert _cross_product_entries.call_count == 1

    @patch("ir.table_entry_builder.MergeTableEntryBuilder._cross_product_entries")
    @patch("ir.table_entry_builder.MergeTableEntryBuilder._add_default_ternary_entry")
    @patch("ir.table_entry_builder.MergeTableEntryBuilder._convert_all_entry_keys_to_ternary")
    def test_merge_two_tables_entries_exact_ternary(
        self, _convert_all_entry_keys_to_ternary, _add_default_ternary_entry, _cross_product_entries, json_path
    ):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 4
        exact_tab1 = tables[0]
        ternary_tab1 = tables[3]
        merge_builder = MergeTableEntryBuilder(irg, exact_tab1, ternary_tab1)
        merge_builder._merge_two_tables_entries(exact_tab1, ternary_tab1)
        assert _convert_all_entry_keys_to_ternary.call_count == 2
        assert _add_default_ternary_entry.call_count == 2
        assert _cross_product_entries.call_count == 1

    @patch("ir.table_entry_builder.MergeTableEntryBuilder._cross_product_entries")
    @patch("ir.table_entry_builder.MergeTableEntryBuilder._add_default_ternary_entry")
    @patch("ir.table_entry_builder.MergeTableEntryBuilder._convert_all_entry_keys_to_ternary")
    def test_merge_two_tables_entries_lpm_ternary(
        self, _convert_all_entry_keys_to_ternary, _add_default_ternary_entry, _cross_product_entries, json_path
    ):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 4
        lpm_tab1 = tables[2]
        ternary_tab1 = tables[3]
        merge_builder = MergeTableEntryBuilder(irg, lpm_tab1, ternary_tab1)
        merge_builder._merge_two_tables_entries(lpm_tab1, ternary_tab1)
        assert _convert_all_entry_keys_to_ternary.call_count == 2
        assert _add_default_ternary_entry.call_count == 2
        assert _cross_product_entries.call_count == 1

    @patch("ir.table_entry_builder.MergeTableEntryBuilder._cross_product_entries")
    @patch("ir.table_entry_builder.MergeTableEntryBuilder._add_default_ternary_entry")
    @patch("ir.table_entry_builder.MergeTableEntryBuilder._convert_all_entry_keys_to_ternary")
    def test_merge_two_tables_entries_ternary_ternary(
        self, _convert_all_entry_keys_to_ternary, _add_default_ternary_entry, _cross_product_entries, json_path
    ):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 5
        ternary_tab1 = tables[3]
        ternary_tab2 = tables[4]
        merge_builder = MergeTableEntryBuilder(irg, ternary_tab1, ternary_tab2)
        merge_builder._merge_two_tables_entries(ternary_tab1, ternary_tab2)
        assert _convert_all_entry_keys_to_ternary.call_count == 2
        assert _add_default_ternary_entry.call_count == 2
        assert _cross_product_entries.call_count == 1
