from dataclasses import dataclass
import pytest
import os, sys
import mock_import
from runtime_CLI import RuntimeAPI

from graph_optimizer.json_manager import JsonManager
from graph_optimizer.runtime_states import RuntimeStates


@dataclass
class CounterReadReturn:
    packets: int


class TestRuntimeStats:
    @pytest.mark.parametrize(
        "json_path",
        [
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "testdata", "simple_test_no_const_action", "test.p4.json"
            )
        ],
    )
    @pytest.mark.parametrize(
        "mapping_path", [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "tmp_mapping.json")]
    )
    def test_retrieve_runtime_states(self, json_path, mapping_path):
        api = RuntimeAPI()
        api.client.bm_mt_get_num_entries.return_value = 1
        api.client.bm_mt_entry_insertion_counter_read.return_value = 1
        api.client.bm_counter_read.return_value = CounterReadReturn(1)
        api.client.bm_get_total_memory.return_value = 1
        api.client.bm_get_total_entry_insertion_bandwidth.return_value = 1
        api.client.bm_mt_get_mapping.return_value = None

        json_manager = JsonManager(api)
        stats = json_manager.retrieve_runtime_states(json_path, mapping_path)
        assert isinstance(stats, RuntimeStates)
        print(stats)
