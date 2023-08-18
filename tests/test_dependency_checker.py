import itertools
from graph_optimizer.pipelet import PipeletGroup
from ir.condition import Condition
import numpy as np
import pytest, sys, os

from ir.action_parameter import FieldParam, HeaderParam
from ir.match_key import MatchKey, MatchType
from ir.action import OptAction
from ir.table import Table
from graph_optimizer.opt_utils import OptUtils
from graph_optimizer.json_manager import JsonManager, JsonPlanner
from graph_optimizer.data_access_info import DataAccessInfo
from commons.types import Probability, TableId, TableName
from typing import List, Set, Tuple
import utils as TestUtils


class TestDataAccessInfo:
    def test_field_written_by_other_false_none(self):
        field = FieldParam(["ipv4", "protocol"])

        data_access_info = DataAccessInfo(match_key=[], action_read=[], action_write=[], has_entry_insertion=False)
        assert not DataAccessInfo._field_written_by_other(field, data_access_info)

    def test_field_written_by_other_false(self):
        field = FieldParam(["ipv4", "protocol"])
        data_access_info = DataAccessInfo(
            match_key=[],
            action_read=[
                FieldParam(["ipv4", "abc"]),
                FieldParam(["tcp", "ttt"]),
                HeaderParam("ipv4"),
                HeaderParam("protocol"),
            ],
            action_write=[
                FieldParam(["ipv4", "ihl"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("protocol"),
            ],
            has_entry_insertion=False,
        )
        assert not DataAccessInfo._field_written_by_other(field, data_access_info)

    def test_field_written_by_other_true_field(self):
        field = FieldParam(["ipv4", "protocol"])

        data_access_info = DataAccessInfo(
            match_key=[],
            action_read=[
                FieldParam(["ipv4", "abc"]),
                FieldParam(["tcp", "ttt"]),
                HeaderParam("ipv4"),
                HeaderParam("protocol"),
            ],
            action_write=[
                FieldParam(["ipv4", "protocol"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("protocol"),
            ],
            has_entry_insertion=False,
        )
        assert DataAccessInfo._field_written_by_other(field, data_access_info)

    def test_field_written_by_other_true_header(self):
        field = FieldParam(["ipv4", "protocol"])

        data_access_info = DataAccessInfo(
            match_key=[],
            action_read=[
                FieldParam(["ipv4", "abc"]),
                FieldParam(["tcp", "ttt"]),
                HeaderParam("ipv4"),
                HeaderParam("protocol"),
            ],
            action_write=[
                FieldParam(["tcp", "protocol"]),
                HeaderParam("ipv4"),
            ],
            has_entry_insertion=False,
        )
        assert DataAccessInfo._field_written_by_other(field, data_access_info)

    def test_field_read_by_other_false_none(self):
        field = FieldParam(["ipv4", "protocol"])

        data_access_info = DataAccessInfo(match_key=[], action_read=[], action_write=[], has_entry_insertion=False)
        assert not DataAccessInfo._field_read_by_other(field, data_access_info)

    def test_field_read_by_other_false(self):
        field = FieldParam(["ipv4", "protocol"])
        data_access_info = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.EXACT, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["ipv4", "abc"]),
                FieldParam(["tcp", "ttt"]),
                HeaderParam("protocol"),
            ],
            action_write=[
                FieldParam(["ipv4", "ihl"]),
                FieldParam(["ipv4", "protocol"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("protocol"),
                HeaderParam("ipv4"),
            ],
            has_entry_insertion=False,
        )
        assert not DataAccessInfo._field_read_by_other(field, data_access_info)

    def test_field_read_by_other_true_field(self):
        field = FieldParam(["ipv4", "protocol"])
        data_access_info = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.EXACT, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["ipv4", "protocol"]),
                FieldParam(["tcp", "ttt"]),
                HeaderParam("protocol"),
            ],
            action_write=[
                FieldParam(["ipv4", "ihl"]),
                FieldParam(["ipv4", "protocol"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("protocol"),
                HeaderParam("ipv4"),
            ],
            has_entry_insertion=False,
        )
        assert DataAccessInfo._field_read_by_other(field, data_access_info)

    def test_field_read_by_other_true_header(self):
        field = FieldParam(["ipv4", "protocol"])
        data_access_info = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.EXACT, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["ipv4", "ttl"]),
                FieldParam(["tcp", "ttt"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["ipv4", "ihl"]),
                FieldParam(["ipv4", "protocol"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("protocol"),
                HeaderParam("ipv4"),
            ],
            has_entry_insertion=False,
        )
        assert DataAccessInfo._field_read_by_other(field, data_access_info)

    def test_field_read_by_other_true_matchkey(self):
        field = FieldParam(["ipv4", "protocol"])
        data_access_info = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.protocol", match_type=MatchType.EXACT, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["ipv4", "aaa"]),
                FieldParam(["tcp", "ttt"]),
                HeaderParam("udp"),
            ],
            action_write=[
                FieldParam(["ipv4", "ihl"]),
                FieldParam(["ipv4", "protocol"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("protocol"),
                HeaderParam("ipv4"),
            ],
            has_entry_insertion=False,
        )
        assert DataAccessInfo._field_read_by_other(field, data_access_info)

    def test_header_read_by_other_false_none(self):
        header = HeaderParam("ipv4")
        data_access_info = DataAccessInfo(match_key=[], action_read=[], action_write=[], has_entry_insertion=False)
        assert not DataAccessInfo._header_read_by_other(header, data_access_info)

    def test_header_read_by_other_false(self):
        header = HeaderParam("ipv4")
        data_access_info = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv5.protocol", match_type=MatchType.EXACT, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["ipv6", "aaa"]),
                FieldParam(["tcp", "ttt"]),
                HeaderParam("udp"),
            ],
            action_write=[
                FieldParam(["ipv4", "ihl"]),
                FieldParam(["ipv4", "protocol"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("protocol"),
                HeaderParam("ipv4"),
            ],
            has_entry_insertion=False,
        )
        assert not DataAccessInfo._header_read_by_other(header, data_access_info)

    def test_header_read_by_other_matchkey(self):
        header = HeaderParam("ipv4")
        data_access_info = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.protocol", match_type=MatchType.EXACT, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["ipv6", "aaa"]),
                FieldParam(["tcp", "ttt"]),
                HeaderParam("udp"),
            ],
            action_write=[
                FieldParam(["ipv4", "ihl"]),
                FieldParam(["ipv4", "protocol"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("protocol"),
                HeaderParam("ipv4"),
            ],
            has_entry_insertion=False,
        )
        assert DataAccessInfo._header_read_by_other(header, data_access_info)

    def test_header_read_by_other_action_read_header(self):
        header = HeaderParam("ipv4")
        data_access_info = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="tcp.protocol", match_type=MatchType.EXACT, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["ipv6", "aaa"]),
                FieldParam(["tcp", "ttt"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["ipv4", "ihl"]),
                FieldParam(["ipv4", "protocol"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("protocol"),
                HeaderParam("ipv4"),
            ],
            has_entry_insertion=False,
        )
        assert DataAccessInfo._header_read_by_other(header, data_access_info)

    def test_header_read_by_other_action_read_field(self):
        header = HeaderParam("ipv4")
        data_access_info = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="tcp.protocol", match_type=MatchType.EXACT, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["ipv6", "aaa"]),
                FieldParam(["ipv4", "ttt"]),
            ],
            action_write=[
                FieldParam(["ipv4", "ihl"]),
                FieldParam(["ipv4", "protocol"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("protocol"),
                HeaderParam("ipv4"),
            ],
            has_entry_insertion=False,
        )
        assert DataAccessInfo._header_read_by_other(header, data_access_info)

    def test_header_written_by_other_false_none(self):
        header = HeaderParam("ipv4")
        data_access_info = DataAccessInfo(match_key=[], action_read=[], action_write=[], has_entry_insertion=False)
        assert not DataAccessInfo._header_written_by_other(header, data_access_info)

    def test_header_written_by_other_false(self):
        header = HeaderParam("ipv4")
        data_access_info = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.protocol", match_type=MatchType.EXACT, global_mask=None, name="test"),
            ],
            action_read=[FieldParam(["ipv4", "ihl"]), FieldParam(["ipv4", "protocol"]), HeaderParam("ipv4")],
            action_write=[
                FieldParam(["tcp", "protocol"]),
                HeaderParam("protocol"),
            ],
            has_entry_insertion=False,
        )
        assert not DataAccessInfo._header_written_by_other(header, data_access_info)

    def test_header_written_by_other_action_write_header(self):
        header = HeaderParam("ipv4")
        data_access_info = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="tcp.protocol", match_type=MatchType.EXACT, global_mask=None, name="test"),
            ],
            action_read=[FieldParam(["tcp", "ihl"]), FieldParam(["tcp", "protocol"]), HeaderParam("tcp")],
            action_write=[
                FieldParam(["tcp", "protocol"]),
                HeaderParam("protocol"),
                HeaderParam("ipv4"),
            ],
            has_entry_insertion=False,
        )
        assert DataAccessInfo._header_written_by_other(header, data_access_info)

    def test_header_written_by_other_action_write_field(self):
        header = HeaderParam("ipv4")
        data_access_info = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="tcp.protocol", match_type=MatchType.EXACT, global_mask=None, name="test"),
            ],
            action_read=[FieldParam(["tcp", "ihl"]), FieldParam(["tcp", "protocol"]), HeaderParam("tcp")],
            action_write=[
                FieldParam(["ipv4", "ihl"]),
                FieldParam(["ipv4", "protocol"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("protocol"),
            ],
            has_entry_insertion=False,
        )
        assert DataAccessInfo._header_written_by_other(header, data_access_info)

    def test_matchkey_written_by_other_false_none(self):
        info1 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
            ],
            action_read=[],
            action_write=[],
            has_entry_insertion=False,
        )
        info2 = DataAccessInfo(match_key=[], action_read=[], action_write=[], has_entry_insertion=False)
        assert not info1._match_key_written_by_other(info2)

    def test_matchkey_written_by_other_false(self):
        info1 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[],
            action_write=[],
            has_entry_insertion=False,
        )
        info2 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("tcp"),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["ipv4", "protocol"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("protocol"),
            ],
            has_entry_insertion=False,
        )
        assert not info1._match_key_written_by_other(info2)

    def test_matchkey_written_by_other_field(self):
        info1 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[],
            action_write=[],
            has_entry_insertion=False,
        )
        info2 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("tcp"),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["ipv4", "ttl"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("protocol"),
            ],
            has_entry_insertion=False,
        )
        assert info1._match_key_written_by_other(info2)

    def test_matchkey_written_by_other_header(self):
        info1 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[],
            action_write=[],
            has_entry_insertion=False,
        )
        info2 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("tcp"),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["tcp", "protocol"]),
                HeaderParam("ipv4"),
            ],
            has_entry_insertion=False,
        )
        assert info1._match_key_written_by_other(info2)

    def test_info_dependency_none(self):
        info1 = DataAccessInfo(match_key=[], action_read=[], action_write=[], has_entry_insertion=False)
        info2 = DataAccessInfo(match_key=[], action_read=[], action_write=[], has_entry_insertion=False)
        assert not info1._has_dependency_with(info2)
        assert not info2._has_dependency_with(info1)

    def test_info_dependency_false(self):
        info1 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "233"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["tcp", "aaaa"]),
                HeaderParam("migration"),
            ],
            has_entry_insertion=False,
        )
        info2 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["tcp", "protocol"]),
                HeaderParam("udp"),
            ],
            has_entry_insertion=False,
        )
        assert not info1._has_dependency_with(info2)
        assert not info2._has_dependency_with(info1)

    def test_info_dependency_read_write_matchkey_field(self):
        info1 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "233"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["tcp", "aaaa"]),
                HeaderParam("migration"),
            ],
            has_entry_insertion=False,
        )
        info2 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["tcp", "sport"]),
                HeaderParam("udp"),
            ],
            has_entry_insertion=False,
        )
        assert info1._has_dependency_with(info2)
        assert info2._has_dependency_with(info1)

    def test_info_dependency_read_write_matchkey_header(self):
        info1 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "233"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["tcp", "aaaa"]),
                HeaderParam("migration"),
            ],
            has_entry_insertion=False,
        )
        info2 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["udp", "dport"]),
                HeaderParam("tcp"),
            ],
            has_entry_insertion=False,
        )
        assert info1._has_dependency_with(info2)
        assert info2._has_dependency_with(info1)

    def test_info_dependency_read_write_field_field(self):
        info1 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "233"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["tcp", "aaaa"]),
                HeaderParam("migration"),
            ],
            has_entry_insertion=False,
        )
        info2 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["tcp", "ihl"]),
                HeaderParam("udp"),
            ],
            has_entry_insertion=False,
        )
        assert info1._has_dependency_with(info2)
        assert info2._has_dependency_with(info1)

    def test_info_dependency_read_write_field_header(self):
        info1 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "233"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["tcp", "aaaa"]),
                HeaderParam("migration"),
            ],
            has_entry_insertion=False,
        )
        info2 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["tcp", "protocol"]),
                HeaderParam("tcp"),
            ],
            has_entry_insertion=False,
        )
        assert info1._has_dependency_with(info2)
        assert info2._has_dependency_with(info1)

    def test_info_dependency_read_write_header_field(self):
        info1 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "233"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["tcp", "aaaa"]),
                HeaderParam("migration"),
            ],
            has_entry_insertion=False,
        )
        info2 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["ipv4", "protocol"]),
                HeaderParam("udp"),
            ],
            has_entry_insertion=False,
        )
        assert info1._has_dependency_with(info2)
        assert info2._has_dependency_with(info1)

    def test_info_dependency_read_write_header_header(self):
        info1 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "233"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["tcp", "aaaa"]),
                HeaderParam("migration"),
            ],
            has_entry_insertion=False,
        )
        info2 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["udp", "protocol"]),
                HeaderParam("ipv4"),
            ],
            has_entry_insertion=False,
        )
        assert info1._has_dependency_with(info2)
        assert info2._has_dependency_with(info1)

    def test_info_dependency_write_write_field_field(self):
        info1 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "233"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["tcp", "aaaa"]),
                HeaderParam("migration"),
            ],
            has_entry_insertion=False,
        )
        info2 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["tcp", "aaaa"]),
                HeaderParam("ipv4"),
            ],
            has_entry_insertion=False,
        )
        assert info1._has_dependency_with(info2)
        assert info2._has_dependency_with(info1)

    def test_info_dependency_write_write_field_header(self):
        info1 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "233"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["tcp", "aaaa"]),
                HeaderParam("migration"),
            ],
            has_entry_insertion=False,
        )
        info2 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["udp", "aaaa"]),
                HeaderParam("tcp"),
            ],
            has_entry_insertion=False,
        )
        assert info1._has_dependency_with(info2)
        assert info2._has_dependency_with(info1)

    def test_info_dependency_write_write_header_field(self):
        info1 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "233"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["tcp", "aaaa"]),
                HeaderParam("migration"),
            ],
            has_entry_insertion=False,
        )
        info2 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["migration", "aaaa"]),
                HeaderParam("udp"),
            ],
            has_entry_insertion=False,
        )
        assert info1._has_dependency_with(info2)
        assert info2._has_dependency_with(info1)

    def test_info_dependency_write_write_header_header(self):
        info1 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "233"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["tcp", "aaaa"]),
                HeaderParam("migration"),
            ],
            has_entry_insertion=False,
        )
        info2 = DataAccessInfo(
            match_key=[
                MatchKey(header="tcp.sport", match_type=MatchType.EXACT, global_mask=None, name="test"),
                MatchKey(header="ipv4.ttl", match_type=MatchType.LPM, global_mask=None, name="test"),
            ],
            action_read=[
                FieldParam(["tcp", "ihl"]),
                FieldParam(["tcp", "protocol"]),
                HeaderParam("ipv4"),
            ],
            action_write=[
                FieldParam(["udp", "aaaa"]),
                HeaderParam("migration"),
            ],
            has_entry_insertion=False,
        )
        assert info1._has_dependency_with(info2)
        assert info2._has_dependency_with(info1)


class TestDependencyChecker:
    @pytest.mark.parametrize(
        "extract_json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "data_access_info_extract", "test.p4.json"
            )
        ],
    )
    def test_extract_data_access_info(self, extract_json_path):
        irg, target = JsonManager.retrieve_presplit(extract_json_path)
        tables = list(irg.get_pipe("ingress").tables)
        assert len(tables) == 1
        info: DataAccessInfo = OptUtils._extract_data_access_info(irg, tables[0])

        match_key = [
            MatchKey(header="ipv4.srcAddr", match_type=MatchType.EXACT, global_mask=None, name="hdr.ipv4.srcAddr"),
        ]

        action_read = [
            FieldParam(["migration", "tabl2_data"]),
            FieldParam(["tcp", "dstPort"]),
            FieldParam(["ipv4", "srcAddr"]),
            FieldParam(["ipv4", "dstAddr"]),
            FieldParam(["ipv4", "protocol"]),
            FieldParam(["tcp", "dstPort"]),
            FieldParam(["tcp", "dstPort"]),
            HeaderParam("ipv4"),
        ]
        action_write = [
            FieldParam(["migration", "tabl1_data"]),
            FieldParam(["tcp", "srcPort"]),
            FieldParam(["scalars", "userMetadata.aaa"]),
            HeaderParam("ipv4"),
        ]

        assert len(info.match_key) == 1
        assert info.match_key[0]._p4cir2json() == match_key[0]._p4cir2json()

        assert len(info.action_read) == len(action_read)
        for i in range(len(action_read)):
            assert action_read[i]._p4cir2json() == info.action_read[i]._p4cir2json()

        assert len(info.action_write) == len(action_write)
        for i in range(len(action_write)):
            assert action_write[i]._p4cir2json() == info.action_write[i]._p4cir2json()

    @pytest.mark.parametrize(
        "match_dep_json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "match_dependency", "test.p4.json")],
    )
    def test_match_dependency(self, match_dep_json_path):
        irg, target = JsonManager.retrieve_presplit(match_dep_json_path)
        tables = list(irg.get_pipe("ingress").tables)
        for i in range(len(tables)):
            assert tables[i].name == f"MyIngress.tab{i+1}"
        assert OptUtils._has_match_dependency(irg, tables[0], tables[1])
        assert not OptUtils._has_match_dependency(irg, tables[1], tables[0])
        assert not OptUtils._has_match_dependency(irg, tables[1], tables[2])
        assert not OptUtils._has_match_dependency(irg, tables[2], tables[1])
        assert OptUtils._has_match_dependency(irg, tables[2], tables[3])
        assert OptUtils._has_match_dependency(irg, tables[3], tables[2])
        assert not OptUtils._has_match_dependency(irg, tables[0], tables[4])
        assert not OptUtils._has_match_dependency(irg, tables[4], tables[0])

    @pytest.mark.parametrize(
        "dep_test_json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "dep_test", "test.p4.json")],
    )
    def test_order_swap(self, dep_test_json_path):
        irg, target = JsonManager.retrieve_presplit(dep_test_json_path)
        tables = list(irg.get_pipe("ingress").tables)
        for i in range(len(tables)):
            assert tables[i].name == f"MyIngress.tab{i+1}"

        # read-read
        assert OptUtils._can_swap_order(irg, tables[0], tables[1])
        assert OptUtils._can_swap_order(irg, tables[1], tables[0])
        # read-write
        assert not OptUtils._can_swap_order(irg, tables[1], tables[2])
        assert not OptUtils._can_swap_order(irg, tables[1], tables[3])
        # write-write
        assert not OptUtils._can_swap_order(irg, tables[3], tables[4])
        assert not OptUtils._can_swap_order(irg, tables[3], tables[5])
        # write-read
        assert not OptUtils._can_swap_order(irg, tables[5], tables[6])
        assert not OptUtils._can_swap_order(irg, tables[5], tables[7])

    @pytest.mark.parametrize(
        "dep_test_json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "simple_dash", "test.p4.json")],
    )
    def test_order_swap_entry_install(self, dep_test_json_path):
        irg, target = JsonManager.retrieve_presplit(dep_test_json_path)
        tables = list(irg.get_pipe("ingress").tables)
        table_name_to_table = {}
        for tab in tables:
            table_name_to_table[tab.name] = tab
        acl1 = table_name_to_table["sirius_ingress.acl_stage1"]
        acl2 = table_name_to_table["sirius_ingress.acl_stage2"]
        acl3 = table_name_to_table["sirius_ingress.acl_stage3"]

        assert OptUtils._can_swap_order(irg, acl1, acl2)
        assert not OptUtils._can_swap_order(irg, acl1, acl3)
        assert not OptUtils._can_swap_order(irg, acl2, acl3)

    def _check_constraints(self, all_orders: List[List[TableId]], constrants: List[Tuple[TableId, TableId]]) -> int:
        """Given a list of reorder plans, check whether each plan satisfies the dependency
        constrants, and return the count of that plans

        - all_orders: All the possible reorder plans ignoring dependency constrants
        - constrants: A list of depdency relations. (i, j) means table_id=i
        must appear before table_id=j
        """
        count = 0
        for order in all_orders:
            count += 1
            for x, y in constrants:
                idx_x = np.argwhere(np.array(order) == x)
                idx_y = np.argwhere(np.array(order) == y)
                if idx_x > idx_y:
                    count -= 1
                    break
        return count

    @pytest.mark.parametrize(
        "topo_sort_json_path",
        [
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "dep_test", "test.p4.json"),
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "match_dependency", "test.p4.json"),
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "data_access_info_extract", "test.p4.json"
            ),
        ],
    )
    def test_topo_sort(self, topo_sort_json_path):
        irg, target = JsonManager.retrieve_presplit(topo_sort_json_path)
        pipelets = JsonPlanner.get_pipelets(irg.get_pipe("ingress"))
        assert len(pipelets) == 1
        tables = pipelets[0].tables

        # get all plans
        all_plans: List[List[TableId]] = []
        for order in itertools.permutations(list(range(0, pipelets[0].length))):
            all_plans.append(list(order))

        # get all constrants
        constrants: List[Tuple[TableId, TableId]] = []
        for i in range(len(tables) - 1):
            for j in range(i + 1, len(tables)):
                if not OptUtils._can_swap_order(irg, tables[i], tables[j]):
                    constrants.append((i, j))

        assert self._check_constraints(all_plans, constrants) == len(list(OptUtils._topo_sort(irg, pipelets[0])))


@pytest.mark.parametrize(
    "strict_match_dep_json_path",
    [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "strict_match_dependency", "test.p4.json")],
)
class TestStrictMatchDependency:
    def test_single_table(self, strict_match_dep_json_path):
        irg, target = JsonManager.retrieve_presplit(strict_match_dep_json_path)
        tables = list(irg.get_pipe("ingress").tables)
        # single table without match key
        info = OptUtils._extract_data_access_info(irg, tables[0])
        strict_match_dep = OptUtils._check_strict_match_dependency([info])
        assert len(strict_match_dep) == 2
        assert strict_match_dep == set(["migration.tabl1_data", "tcp.dstPort"])
        # single table with match keys and two actions
        info = OptUtils._extract_data_access_info(irg, tables[1])
        strict_match_dep = OptUtils._check_strict_match_dependency([info])
        assert len(strict_match_dep) == 4
        assert strict_match_dep == set(["migration.tabl2_data", "tcp.srcPort", "tcp.dstPort", "tcp.window"])

    def test_multi_tables(self, strict_match_dep_json_path):
        irg, target = JsonManager.retrieve_presplit(strict_match_dep_json_path)
        tables = list(irg.get_pipe("ingress").tables)
        # two tables
        infos: List[DataAccessInfo] = []
        for i in range(2):
            infos.append(OptUtils._extract_data_access_info(irg, tables[i]))
        strict_match_dep = OptUtils._check_strict_match_dependency(infos)
        assert len(strict_match_dep) == 4
        assert strict_match_dep == set(["migration.tabl2_data", "migration.tabl1_data", "tcp.dstPort", "tcp.window"])
        # three tables
        infos: List[DataAccessInfo] = []
        for i in range(3):
            infos.append(OptUtils._extract_data_access_info(irg, tables[i]))
        strict_match_dep = OptUtils._check_strict_match_dependency(infos)
        assert len(strict_match_dep) == 4
        assert strict_match_dep == set(["migration.tabl2_data", "migration.tabl1_data", "tcp.dstPort", "tcp.window"])


class TestConditionKey:
    @pytest.mark.parametrize(
        "json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "condition_extract", "test.p4.json")],
    )
    def test_extract_condition_key(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        conditions = list(irg.get_pipe("ingress").conditions)
        name2cond = {cond.name: cond for cond in conditions}
        # if (hdr.ipv4.isValid())
        ipv4_valid = name2cond["node_2"]
        mkeys = list(OptUtils._extract_condition_match_key(irg, ipv4_valid))
        assert len(mkeys) == 1
        expected_key = MatchKey(
            header="ipv4.$valid$", match_type=MatchType.EXACT, global_mask=None, name="hdr.ipv4.$valid$"
        )
        assert mkeys[0] == expected_key

        # if (hdr.tcp.srcPort == 80)
        src_port = name2cond["node_3"]
        mkeys = list(OptUtils._extract_condition_match_key(irg, src_port))
        assert len(mkeys) == 1
        expected_key = MatchKey(
            header="tcp.srcPort", match_type=MatchType.EXACT, global_mask=None, name="hdr.tcp.srcPort"
        )
        assert mkeys[0] == expected_key

        # if (hdr.tcp.dstPort + 3 > 60)
        dst_port = name2cond["node_4"]
        mkeys = list(OptUtils._extract_condition_match_key(irg, dst_port))
        assert len(mkeys) == 1
        expected_key = MatchKey(
            header="tcp.dstPort", match_type=MatchType.EXACT, global_mask=None, name="hdr.tcp.dstPort"
        )
        assert mkeys[0] == expected_key

        # if (hdr.tcp.dstPort + meta.aaa > 60)
        dst_port_aaa = name2cond["node_5"]
        mkeys = list(OptUtils._extract_condition_match_key(irg, dst_port_aaa))
        assert len(mkeys) == 2
        expected_key = [
            MatchKey(header="tcp.dstPort", match_type=MatchType.EXACT, global_mask=None, name="hdr.tcp.dstPort"),
            MatchKey(header="scalars.userMetadata.aaa", match_type=MatchType.EXACT, global_mask=None, name="meta.aaa"),
        ]
        assert set(mkeys) == set(expected_key)

        # if (standard_metadata.ingress_port != 2)
        stdmeta = name2cond["node_6"]
        mkeys = list(OptUtils._extract_condition_match_key(irg, stdmeta))
        assert len(mkeys) == 1
        expected_key = [
            MatchKey(
                header="standard_metadata.ingress_port",
                match_type=MatchType.EXACT,
                global_mask=None,
                name="standard_metadata.ingress_port",
            )
        ]
        assert mkeys == expected_key

        # if (meta.aaa == 100 && meta.aaa == 110)
        meta_aaa = name2cond["node_7"]
        mkeys = list(OptUtils._extract_condition_match_key(irg, meta_aaa))
        assert len(mkeys) == 1
        expected_key = [
            MatchKey(header="scalars.userMetadata.aaa", match_type=MatchType.EXACT, global_mask=None, name="meta.aaa")
        ]
        assert mkeys == expected_key

        # if (meta.aaa == 100 && meta.aaa == 110)
        tcp_valid = name2cond["node_8"]
        mkeys = list(OptUtils._extract_condition_match_key(irg, tcp_valid))
        assert len(mkeys) == 1
        expected_key = [
            MatchKey(header="tcp.$valid$", match_type=MatchType.EXACT, global_mask=None, name="hdr.tcp.$valid$")
        ]
        assert mkeys == expected_key

        # if (hdr.ipv4.ttl > 1 && hdr.tcp.dstPort != 4 || hdr.tcp.srcPort > 5)
        tcp_valid = name2cond["node_10"]
        mkeys = list(OptUtils._extract_condition_match_key(irg, tcp_valid))
        assert len(mkeys) == 3
        expected_key = [
            MatchKey(header="ipv4.ttl", match_type=MatchType.EXACT, global_mask=None, name="hdr.ipv4.ttl"),
            MatchKey(header="tcp.dstPort", match_type=MatchType.EXACT, global_mask=None, name="hdr.tcp.dstPort"),
            MatchKey(header="tcp.srcPort", match_type=MatchType.EXACT, global_mask=None, name="hdr.tcp.srcPort"),
        ]
        assert set(mkeys) == set(expected_key)


@pytest.mark.parametrize(
    "json_path", [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "merge", "test.p4.json")]
)
class TestActionMergePipelet:
    def test_merge_actions_from_multiple_tables(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 2
        exact_tab1 = tables[0]
        exact_tab2 = tables[1]
        assert isinstance(exact_tab1, Table) and isinstance(exact_tab2, Table)
        tab1_act1 = irg.action_id_to_action[exact_tab1.action_ids[0]]
        tab1_act2 = irg.action_id_to_action[exact_tab1.action_ids[1]]
        tab2_act1 = irg.action_id_to_action[exact_tab2.action_ids[0]]
        tab2_act2 = irg.action_id_to_action[exact_tab2.action_ids[1]]

        merged_actions: List[Tuple[OptAction, Probability]] = OptUtils._merge_actions_pipelet(
            irg, [exact_tab1, exact_tab2]
        )
        assert len(merged_actions) == 4
        mact0 = merged_actions[0][0]
        mact1 = merged_actions[1][0]
        mact2 = merged_actions[2][0]
        mact3 = merged_actions[3][0]
        assert mact0.name == "merged_MyIngress.tab_exact1_act1_MyIngress.tab_exact2_act1"
        assert mact1.name == "merged_MyIngress.tab_exact1_act1_MyIngress.tab_exact2_act2"
        assert mact2.name == "merged_MyIngress.tab_exact1_act2_MyIngress.tab_exact2_act1"
        assert mact3.name == "merged_MyIngress.tab_exact1_act2_MyIngress.tab_exact2_act2"

        assert mact0.runtime_data == tab1_act1.runtime_data + tab2_act1.runtime_data
        assert mact1.runtime_data == tab1_act1.runtime_data + tab2_act2.runtime_data
        assert mact2.runtime_data == tab1_act2.runtime_data + tab2_act1.runtime_data
        assert mact3.runtime_data == tab1_act2.runtime_data + tab2_act2.runtime_data

        assert mact0.primitives == tab1_act1.primitives + tab2_act1.primitives
        assert mact1.primitives == tab1_act1.primitives + tab2_act2.primitives
        assert mact2.primitives == tab1_act2.primitives + tab2_act1.primitives
        assert mact3.primitives == tab1_act2.primitives + tab2_act2.primitives

    def test_merge_validality(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 4
        tab_exact2 = tables[1]
        tab_lpm1 = tables[2]
        tab_ternary1 = tables[3]
        assert isinstance(tab_exact2, Table) and tab_exact2.name == "MyIngress.tab_exact2"
        assert isinstance(tab_lpm1, Table) and tab_lpm1.name == "MyIngress.tab_lpm1"
        assert isinstance(tab_ternary1, Table) and tab_ternary1.name == "MyIngress.tab_ternary1"

        assert not OptUtils._can_merge(irg, tab_lpm1, tab_ternary1)
        assert OptUtils._can_merge(irg, tab_ternary1, tab_lpm1)
        assert OptUtils._can_merge(irg, tab_exact2, tab_lpm1)
        assert OptUtils._can_merge(irg, tab_lpm1, tab_exact2)

    def test_cache_validality(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 5
        tab_exact1 = tables[0]
        tab_exact2 = tables[1]
        tab_lpm1 = tables[2]
        tab_ternary1 = tables[3]
        tab_ternary2 = tables[4]
        assert isinstance(tab_exact1, Table) and tab_exact1.name == "MyIngress.tab_exact1"
        assert isinstance(tab_exact2, Table) and tab_exact2.name == "MyIngress.tab_exact2"
        assert isinstance(tab_lpm1, Table) and tab_lpm1.name == "MyIngress.tab_lpm1"
        assert isinstance(tab_ternary1, Table) and tab_ternary1.name == "MyIngress.tab_ternary1"
        assert isinstance(tab_ternary2, Table) and tab_ternary2.name == "MyIngress.tab_ternary2"

        assert not OptUtils._can_cache(irg, [tab_lpm1, tab_ternary1])
        assert OptUtils._can_cache(irg, [tab_ternary1, tab_lpm1])
        assert OptUtils._can_cache(irg, [tab_exact2, tab_lpm1])
        assert OptUtils._can_cache(irg, [tab_lpm1, tab_exact2])
        assert not OptUtils._can_cache(irg, [tab_lpm1, tab_ternary1, tab_exact1])
        assert not OptUtils._can_cache(irg, [tab_lpm1, tab_ternary1, tab_exact2])
        assert OptUtils._can_cache(irg, [tab_ternary1, tab_lpm1, tab_ternary2])
        assert OptUtils._can_cache(irg, [tab_ternary1, tab_lpm1, tab_exact2])
        assert OptUtils._can_cache(irg, [tab_ternary1, tab_ternary2])
        assert not OptUtils._can_cache(irg, [tab_exact1, tab_ternary1, tab_ternary2])


@pytest.mark.parametrize(
    "json_path",
    [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "pipelet_pipelet_group", "test.p4.json")],
)
class TestActionMergePipeletGroup:
    def test_merge_actions_for_pipelet_single_if(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tab_conds = ingress_graph.name_to_normal_node
        """
        if (hdr.tcp.srcPort == 80) {
            tab06.apply();
        }
        """
        merged_actions: List[Tuple[OptAction, Probability]] = OptUtils._merge_actions_pipelet_group(
            irg, ingress_graph, tab_conds["node_9"], tab_conds["MyIngress.tab08"]
        )
        tab06_act = irg.action_id_to_action[tab_conds["MyIngress.tab06"].action_ids[0]]

        assert len(merged_actions) == 2
        mact0 = merged_actions[0][0]
        mact1 = merged_actions[1][0]
        assert mact0.name == "merged_node_9_true_MyIngress.common_act"
        assert mact1.name == "merged_node_9_true_NoAction"

        assert mact0.runtime_data == tab06_act.runtime_data
        assert mact1.runtime_data == []

        assert mact0.primitives == tab06_act.primitives
        assert mact1.primitives == []

    def test_merge_actions_table_if(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tab_conds = ingress_graph.name_to_normal_node
        """
        tab04.apply();
        tab05.apply();
        if (hdr.tcp.srcPort == 80) {
            tab06.apply();
        }
        """
        merged_actions: List[Tuple[OptAction, Probability]] = OptUtils._merge_actions_pipelet_group(
            irg, ingress_graph, tab_conds["MyIngress.tab04"], tab_conds["MyIngress.tab08"]
        )
        tab04_act = irg.action_id_to_action[tab_conds["MyIngress.tab04"].action_ids[0]]
        tab05_act = irg.action_id_to_action[tab_conds["MyIngress.tab05"].action_ids[0]]
        tab06_act = irg.action_id_to_action[tab_conds["MyIngress.tab06"].action_ids[0]]

        assert len(merged_actions) == 8
        mact0 = merged_actions[0][0]
        mact1 = merged_actions[1][0]
        mact2 = merged_actions[2][0]
        mact3 = merged_actions[3][0]
        mact4 = merged_actions[4][0]
        mact5 = merged_actions[5][0]
        mact6 = merged_actions[6][0]
        mact7 = merged_actions[7][0]
        assert mact0.name == "merged_MyIngress.common_act_MyIngress.common_act_node_9_true_MyIngress.common_act"
        assert mact1.name == "merged_MyIngress.common_act_MyIngress.common_act_node_9_true_NoAction"
        assert mact2.name == "merged_MyIngress.common_act_NoAction_node_9_true_MyIngress.common_act"
        assert mact3.name == "merged_MyIngress.common_act_NoAction_node_9_true_NoAction"
        assert mact4.name == "merged_NoAction_MyIngress.common_act_node_9_true_MyIngress.common_act"
        assert mact5.name == "merged_NoAction_MyIngress.common_act_node_9_true_NoAction"
        assert mact6.name == "merged_NoAction_NoAction_node_9_true_MyIngress.common_act"
        assert mact7.name == "merged_NoAction_NoAction_node_9_true_NoAction"

        assert mact0.runtime_data == tab04_act.runtime_data + tab05_act.runtime_data + tab06_act.runtime_data
        assert mact1.runtime_data == tab04_act.runtime_data + tab05_act.runtime_data
        assert mact2.runtime_data == tab04_act.runtime_data + tab06_act.runtime_data
        assert mact3.runtime_data == tab04_act.runtime_data
        assert mact4.runtime_data == tab05_act.runtime_data + tab06_act.runtime_data
        assert mact5.runtime_data == tab05_act.runtime_data
        assert mact6.runtime_data == tab06_act.runtime_data
        assert mact7.runtime_data == []

        assert mact0.primitives == tab04_act.primitives + tab05_act.primitives + tab06_act.primitives
        assert mact1.primitives == tab04_act.primitives + tab05_act.primitives
        assert mact2.primitives == tab04_act.primitives + tab06_act.primitives
        assert mact3.primitives == tab04_act.primitives
        assert mact4.primitives == tab05_act.primitives + tab06_act.primitives
        assert mact5.primitives == tab05_act.primitives
        assert mact6.primitives == tab06_act.primitives
        assert mact7.primitives == []

    def test_merge_actions_if_table(self, json_path):
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
        merged_actions: List[Tuple[OptAction, Probability]] = OptUtils._merge_actions_pipelet_group(
            irg, ingress_graph, tab_conds["node_12"], tab_conds["MyIngress.tab08"]
        )
        tab18_act = irg.action_id_to_action[tab_conds["MyIngress.tab18"].action_ids[0]]
        tab19_act = irg.action_id_to_action[tab_conds["MyIngress.tab19"].action_ids[0]]
        tab20_act = irg.action_id_to_action[tab_conds["MyIngress.tab20"].action_ids[0]]

        assert len(merged_actions) == 10
        mact0 = merged_actions[0][0]
        mact1 = merged_actions[1][0]
        mact2 = merged_actions[2][0]
        mact3 = merged_actions[3][0]
        mact4 = merged_actions[4][0]
        mact5 = merged_actions[5][0]
        mact6 = merged_actions[6][0]
        mact7 = merged_actions[7][0]
        mact8 = merged_actions[8][0]
        mact9 = merged_actions[9][0]
        assert mact0.name == "merged_node_12_true_MyIngress.common_act_MyIngress.common_act_MyIngress.common_act"
        assert mact1.name == "merged_node_12_true_MyIngress.common_act_MyIngress.common_act_NoAction"
        assert mact2.name == "merged_node_12_true_MyIngress.common_act_NoAction_MyIngress.common_act"
        assert mact3.name == "merged_node_12_true_MyIngress.common_act_NoAction_NoAction"
        assert mact4.name == "merged_node_12_true_NoAction_MyIngress.common_act_MyIngress.common_act"
        assert mact5.name == "merged_node_12_true_NoAction_MyIngress.common_act_NoAction"
        assert mact6.name == "merged_node_12_true_NoAction_NoAction_MyIngress.common_act"
        assert mact7.name == "merged_node_12_true_NoAction_NoAction_NoAction"
        assert mact8.name == "merged_node_12_false_MyIngress.common_act"
        assert mact9.name == "merged_node_12_false_NoAction"

        assert mact0.runtime_data == tab18_act.runtime_data + tab19_act.runtime_data + tab20_act.runtime_data
        assert mact1.runtime_data == tab18_act.runtime_data + tab19_act.runtime_data
        assert mact2.runtime_data == tab18_act.runtime_data + tab20_act.runtime_data
        assert mact3.runtime_data == tab18_act.runtime_data
        assert mact4.runtime_data == tab19_act.runtime_data + tab20_act.runtime_data
        assert mact5.runtime_data == tab19_act.runtime_data
        assert mact6.runtime_data == tab20_act.runtime_data
        assert mact7.runtime_data == []
        assert mact8.runtime_data == tab20_act.runtime_data
        assert mact9.runtime_data == []

        assert mact0.primitives == tab18_act.primitives + tab19_act.primitives + tab20_act.primitives
        assert mact1.primitives == tab18_act.primitives + tab19_act.primitives
        assert mact2.primitives == tab18_act.primitives + tab20_act.primitives
        assert mact3.primitives == tab18_act.primitives
        assert mact4.primitives == tab19_act.primitives + tab20_act.primitives
        assert mact5.primitives == tab19_act.primitives
        assert mact6.primitives == tab20_act.primitives
        assert mact7.primitives == []
        assert mact8.primitives == tab20_act.primitives
        assert mact9.primitives == []

    def test_merge_actions_if_else(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tab_conds = ingress_graph.name_to_normal_node
        """
        if (hdr.tcp.srcPort == 120) {
            tab16.apply();
        } else {
            tab17.apply();
        }
        """
        merged_actions: List[Tuple[OptAction, Probability]] = OptUtils._merge_actions_pipelet_group(
            irg, ingress_graph, tab_conds["node_28"], ingress_graph.sink
        )
        tab16_act = irg.action_id_to_action[tab_conds["MyIngress.tab16"].action_ids[0]]
        tab17_act = irg.action_id_to_action[tab_conds["MyIngress.tab17"].action_ids[0]]

        assert len(merged_actions) == 4
        mact0 = merged_actions[0][0]
        mact1 = merged_actions[1][0]
        mact2 = merged_actions[2][0]
        mact3 = merged_actions[3][0]
        assert mact0.name == "merged_node_28_true_MyIngress.common_act"
        assert mact1.name == "merged_node_28_true_NoAction"
        assert mact2.name == "merged_node_28_false_MyIngress.common_act"
        assert mact3.name == "merged_node_28_false_NoAction"

        assert mact0.runtime_data == tab16_act.runtime_data
        assert mact1.runtime_data == []
        assert mact2.runtime_data == tab17_act.runtime_data
        assert mact3.runtime_data == []

        assert mact0.primitives == tab16_act.primitives
        assert mact1.primitives == []
        assert mact2.primitives == tab17_act.primitives
        assert mact3.primitives == []

    def test_merge_actions_if_elseif_else(self, json_path):
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
        merged_actions: List[Tuple[OptAction, Probability]] = OptUtils._merge_actions_pipelet_group(
            irg, ingress_graph, tab_conds["node_26"], ingress_graph.sink
        )
        tab15_act = irg.action_id_to_action[tab_conds["MyIngress.tab16"].action_ids[0]]
        tab16_act = irg.action_id_to_action[tab_conds["MyIngress.tab16"].action_ids[0]]
        tab17_act = irg.action_id_to_action[tab_conds["MyIngress.tab17"].action_ids[0]]

        assert len(merged_actions) == 6
        mact0 = merged_actions[0][0]
        mact1 = merged_actions[1][0]
        mact2 = merged_actions[2][0]
        mact3 = merged_actions[3][0]
        mact4 = merged_actions[4][0]
        mact5 = merged_actions[5][0]
        assert mact0.name == "merged_node_26_true_MyIngress.common_act"
        assert mact1.name == "merged_node_26_true_NoAction"
        assert mact2.name == "merged_node_26_false_node_28_true_MyIngress.common_act"
        assert mact3.name == "merged_node_26_false_node_28_true_NoAction"
        assert mact4.name == "merged_node_26_false_node_28_false_MyIngress.common_act"
        assert mact5.name == "merged_node_26_false_node_28_false_NoAction"

        assert mact0.runtime_data == tab15_act.runtime_data
        assert mact1.runtime_data == []
        assert mact2.runtime_data == tab16_act.runtime_data
        assert mact3.runtime_data == []
        assert mact4.runtime_data == tab17_act.runtime_data
        assert mact5.runtime_data == []

        assert mact0.primitives == tab15_act.primitives
        assert mact1.primitives == []
        assert mact2.primitives == tab16_act.primitives
        assert mact3.primitives == []
        assert mact4.primitives == tab17_act.primitives
        assert mact5.primitives == []

    def test_merge_actions_switch(self, json_path):
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
        merged_actions: List[Tuple[OptAction, Probability]] = OptUtils._merge_actions_pipelet_group(
            irg, ingress_graph, tab_conds["MyIngress.tab_switch"], tab_conds["node_24"]
        )
        switch_common_act = irg.action_id_to_action[tab_conds["MyIngress.tab_switch"].action_ids[0]]
        switch_decrement_ttl = irg.action_id_to_action[tab_conds["MyIngress.tab_switch"].action_ids[1]]
        switch_increment_ttl = irg.action_id_to_action[tab_conds["MyIngress.tab_switch"].action_ids[2]]
        switch_noaction = irg.action_id_to_action[tab_conds["MyIngress.tab_switch"].action_ids[3]]
        tab11_act = irg.action_id_to_action[tab_conds["MyIngress.tab11"].action_ids[0]]
        tab12_act = irg.action_id_to_action[tab_conds["MyIngress.tab12"].action_ids[0]]
        tab13_act = irg.action_id_to_action[tab_conds["MyIngress.tab13"].action_ids[0]]
        tab21_act = irg.action_id_to_action[tab_conds["MyIngress.tab21"].action_ids[0]]

        assert len(merged_actions) == 9
        mact0 = merged_actions[0][0]
        mact1 = merged_actions[1][0]
        mact2 = merged_actions[2][0]
        mact3 = merged_actions[3][0]
        mact4 = merged_actions[4][0]
        mact5 = merged_actions[5][0]
        mact6 = merged_actions[6][0]
        mact7 = merged_actions[7][0]
        mact8 = merged_actions[8][0]
        assert mact0.name == "merged_MyIngress.common_act_MyIngress.common_act_MyIngress.common_act"
        assert mact1.name == "merged_MyIngress.common_act_MyIngress.common_act_NoAction"
        assert mact2.name == "merged_MyIngress.common_act_NoAction_MyIngress.common_act"
        assert mact3.name == "merged_MyIngress.common_act_NoAction_NoAction"
        assert mact4.name == "merged_MyIngress.increment_ttl_MyIngress.common_act"
        assert mact5.name == "merged_MyIngress.increment_ttl_NoAction"
        assert mact6.name == "merged_MyIngress.decrement_ttl_MyIngress.common_act"
        assert mact7.name == "merged_MyIngress.decrement_ttl_NoAction"
        assert mact8.name == "merged_NoAction"

        assert mact0.runtime_data == switch_common_act.runtime_data + tab11_act.runtime_data + tab12_act.runtime_data
        assert mact1.runtime_data == switch_common_act.runtime_data + tab11_act.runtime_data
        assert mact2.runtime_data == switch_common_act.runtime_data + tab12_act.runtime_data
        assert mact3.runtime_data == switch_common_act.runtime_data
        assert mact4.runtime_data == switch_increment_ttl.runtime_data + tab13_act.runtime_data
        assert mact5.runtime_data == switch_increment_ttl.runtime_data
        assert mact6.runtime_data == switch_decrement_ttl.runtime_data + tab21_act.runtime_data
        assert mact7.runtime_data == switch_decrement_ttl.runtime_data
        assert mact8.runtime_data == switch_noaction.runtime_data

        assert mact0.primitives == switch_common_act.primitives + tab11_act.primitives + tab12_act.primitives
        assert mact1.primitives == switch_common_act.primitives + tab11_act.primitives
        assert mact2.primitives == switch_common_act.primitives + tab12_act.primitives
        assert mact3.primitives == switch_common_act.primitives
        assert mact4.primitives == switch_increment_ttl.primitives + tab13_act.primitives
        assert mact5.primitives == switch_increment_ttl.primitives
        assert mact6.primitives == switch_decrement_ttl.primitives + tab21_act.primitives
        assert mact7.primitives == switch_decrement_ttl.primitives
        assert mact8.primitives == switch_noaction.primitives


class TestGroupCacheKey:
    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "pipelet_pipelet_group", "test.p4.json"
            )
        ],
    )
    def test_group_cache_key_if_elseif_else(self, json_path):
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
        cache_keys: Set[MatchKey] = OptUtils._get_group_cache_match_key(
            irg,
            [
                tab_conds["node_26"],
                tab_conds["node_28"],
                tab_conds["MyIngress.tab14"],
                tab_conds["MyIngress.tab15"],
                tab_conds["MyIngress.tab16"],
                tab_conds["MyIngress.tab17"],
            ],
        )

        assert len(cache_keys) == 2
        assert cache_keys == {
            MatchKey(header="tcp.srcPort", match_type=MatchType.EXACT, global_mask=None, name="hdr.tcp.srcPort"),
            MatchKey(header="ipv4.srcAddr", match_type=MatchType.EXACT, global_mask=None, name="hdr.ipv4.srcAddr"),
        }

    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "pipelet_pipelet_group", "test.p4.json"
            )
        ],
    )
    def test_group_cache_key_switch_table(self, json_path):
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
        cache_keys: Set[MatchKey] = OptUtils._get_group_cache_match_key(
            irg,
            [
                tab_conds["MyIngress.tab_switch"],
                tab_conds["MyIngress.tab11"],
                tab_conds["MyIngress.tab12"],
                tab_conds["MyIngress.tab13"],
                tab_conds["MyIngress.tab21"],
            ],
        )
        assert len(cache_keys) == 2
        assert cache_keys == {
            MatchKey(header="ipv4.srcAddr", match_type=MatchType.EXACT, global_mask=None, name="hdr.ipv4.srcAddr"),
            MatchKey(header="ipv4.ttl", match_type=MatchType.EXACT, global_mask=None, name="hdr.ipv4.ttl"),
        }

    @pytest.mark.parametrize(
        "json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "condition_extract", "test.p4.json")],
    )
    def test_group_cache_complex_condition(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tab_conds = ingress_graph.name_to_normal_node
        cache_keys: Set[MatchKey] = OptUtils._get_group_cache_match_key(
            irg,
            [
                tab_conds["node_2"],
                tab_conds["node_3"],
                tab_conds["node_4"],
                tab_conds["node_5"],
                tab_conds["node_6"],
                tab_conds["node_7"],
                tab_conds["node_8"],
                tab_conds["MyIngress.tab01"],
            ],
        )
        assert len(cache_keys) == 7
        assert cache_keys == {
            MatchKey(header="ipv4.$valid$", match_type=MatchType.EXACT, global_mask=None, name="hdr.ipv4.$valid$"),
            MatchKey(header="tcp.srcPort", match_type=MatchType.EXACT, global_mask=None, name="hdr.tcp.srcPort"),
            MatchKey(header="tcp.dstPort", match_type=MatchType.EXACT, global_mask=None, name="hdr.tcp.dstPort"),
            MatchKey(header="scalars.userMetadata.aaa", match_type=MatchType.EXACT, global_mask=None, name="meta.aaa"),
            MatchKey(
                header="standard_metadata.ingress_port",
                match_type=MatchType.EXACT,
                global_mask=None,
                name="standard_metadata.ingress_port",
            ),
            MatchKey(header="tcp.$valid$", match_type=MatchType.EXACT, global_mask=None, name="hdr.tcp.$valid$"),
            MatchKey(header="ipv4.srcAddr", match_type=MatchType.EXACT, global_mask=None, name="hdr.ipv4.srcAddr"),
        }

    @pytest.mark.parametrize(
        "json_path",
        [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "condition_extract", "test.p4.json")],
    )
    def test_group_cache_complex_condition2(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tab_conds = ingress_graph.name_to_normal_node
        cache_keys: Set[MatchKey] = OptUtils._get_group_cache_match_key(
            irg, [tab_conds["node_10"], tab_conds["MyIngress.tab02"]]
        )
        assert len(cache_keys) == 7
        assert cache_keys == {
            MatchKey(header="ipv4.$valid$", match_type=MatchType.EXACT, global_mask=None, name="hdr.ipv4.$valid$"),
            MatchKey(header="tcp.srcPort", match_type=MatchType.EXACT, global_mask=None, name="hdr.tcp.srcPort"),
            MatchKey(header="tcp.dstPort", match_type=MatchType.EXACT, global_mask=None, name="hdr.tcp.dstPort"),
            MatchKey(header="scalars.userMetadata.aaa", match_type=MatchType.EXACT, global_mask=None, name="meta.aaa"),
            MatchKey(
                header="standard_metadata.ingress_port",
                match_type=MatchType.EXACT,
                global_mask=None,
                name="standard_metadata.ingress_port",
            ),
            MatchKey(header="ipv4.ttl", match_type=MatchType.EXACT, global_mask=None, name="hdr.ipv4.ttl"),
            MatchKey(header="ipv4.srcAddr", match_type=MatchType.EXACT, global_mask=None, name="hdr.ipv4.srcAddr"),
        }
