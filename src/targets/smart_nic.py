from __future__ import annotations
import math
from functools import lru_cache

from commons.constants import DeviceTargetType
from commons.types import LatencyPdf
from commons.metric import *
from ir.match_key import MatchType
from ir.condition import Condition
from targets.driver_api import eval_entry_cost, get_mitigation_cost
from targets.target_base import UnsopportedTableError, TargetBase, MultiTargetBase
import commons.yaml_config as YamlConfig

from typing import TYPE_CHECKING, Dict

if TYPE_CHECKING:
    from ir.table import Table


def latencies_list_add_item(latencies_list, latency, priority):

    i = 0
    latencies_list_len = len(latencies_list)

    while i < latencies_list_len and latencies_list[i][0] <= latency:

        if latencies_list[i][0] == latency:
            latencies_list[i] = (latency, latencies_list[i][1] + priority)
            return
        i += 1

    latencies_list.insert(i, (latency, priority))


class HwSteering(TargetBase):
    def __init__(self):
        self.supported_actions = {"goto", "drop", "modify", "na", "encap"}
        self.supported_keys = {"ipv4.proto", "ipv4.dst", "ipv4.src", "tcp.sport", "tcp.dport"}
        self.memory_size: Bytes = YamlConfig.HW_MEM_SIZE
        self.base_insertion_latency: NanoSec = YamlConfig.HW_BASE_INSERT_LAT
        self.base_datapath_latency: NanoSec = YamlConfig.HW_BASE_DATAPATH_LAT
        self.hash_next_lookup_panelty: NanoSec = YamlConfig.HW_HASH_NEXT_LOOKUP_PANELTY
        self.supported_match_types = ["exact", "lpm", "ternary", "range"]
        self.parallel_steering_pipes = YamlConfig.HW_STEERING_PIPES
        self.parallel_treads_per_core = YamlConfig.HW_THREAD_PER_CORE
        self.lookup_latency: NanoSec = YamlConfig.HW_LOOKUP_LAT

    # singleton
    def __new__(cls):
        if not hasattr(cls, "instance"):
            cls.instance = super(HwSteering, cls).__new__(cls)
        return cls.instance

    @property
    def name(self) -> str:
        return self.__class__.__name__

    @property
    def ctx(self) -> int:
        return 0

    def set_parse_graph(self):
        """in charge of estimating supported parsing nodes, and latency implications"""
        self.supported_keys = []
        self.parser_latency = 0

    def _validate_table(self, table: Table):
        message_actions = ""
        for (action, prob) in table.action_iterator:
            for primitive in action.primitives:
                if primitive.op not in self.supported_actions:
                    message_actions += f"\n--{primitive.op}"
        if message_actions != "":
            message_actions = f"unsupported actions:{message_actions}"

        message_keys = ""
        for mkey in table._keys:
            if mkey.header not in self.supported_keys or mkey.match_type not in self.supported_match_types:
                message_keys += f"\n--{mkey.header}"
        if message_keys != "":
            message_keys = f"unsupported keys:{message_keys}"

        message = message_keys + message_actions
        if message != "":
            raise UnsopportedTableError(table, target=self, reason=message)

    def get_memory_footprint(self, table: Table) -> Bytes:
        max_memory_foorprint = -math.inf
        # On dRMT devices, the memory can be dynamically allocated
        assert table.current_size != None, f"The current size of table {table.name} was not set."
        allocated_entries = (
            math.ceil(table.current_size / YamlConfig.HW_TABLE_SIZE_STEP) * YamlConfig.HW_TABLE_SIZE_STEP
        )

        for (action, prob) in table.action_iterator:
            base_actions = action.primitives
            (_, memory_footprint, _, _) = eval_entry_cost(self, table.keys, base_actions)

            if memory_footprint > max_memory_foorprint:
                max_memory_foorprint = memory_footprint

        return int(max_memory_foorprint * allocated_entries)

    def get_mitigation_latency(self, next_target: TargetBase) -> NanoSec:
        return get_mitigation_cost(self, next_target)

    def latency_eval(self, table: Table) -> LatencyPdf:
        # review !!
        if isinstance(table, Condition):
            return [(self.base_datapath_latency, 1)]

        latency_list: LatencyPdf = []
        remaining_prob = 1.0
        for (action, prob) in table.action_iterator:
            base_actions = action.primitives
            (latency, _, _, _) = eval_entry_cost(self, table.keys, base_actions)
            remaining_prob -= prob
            latencies_list_add_item(latency_list, latency, prob)

        return latency_list

    def get_inter_packet_gap(self, packet_latency_pdf: LatencyPdf) -> NanoSec:
        average_lat = 0.0
        for l, p in packet_latency_pdf:
            average_lat += l * p
        return int((average_lat / self.parallel_steering_pipes) / self.parallel_treads_per_core)


class SwSteering(TargetBase):
    def __init__(self):
        self.supported_actions = ["goto", "drop", "modify", "na", "learn", "encap"]  # TODO - any action?
        self.supported_keys = []
        self.arm_cores = YamlConfig.SW_ARM_CORES
        self.memory_size: Bytes = YamlConfig.SW_MEM_SIZE
        self.base_insertion_latency: NanoSec = YamlConfig.SW_BASE_INSERT_LAT
        self.base_latency: NanoSec = YamlConfig.SW_BASE_LAT
        self.hash_next_lookup_panelty: NanoSec = YamlConfig.SW_HASH_NEXT_LOOKUP_PANELTY
        self.parser_latency: NanoSec = YamlConfig.SW_PARSER_LAT
        self.supported_match_types = [
            MatchType.EXACT,
            MatchType.LPM,
            MatchType.TERNARY,
            MatchType.RANGE,
        ]  # TODO handle/profile ternary?

    # singleton
    def __new__(cls):
        if not hasattr(cls, "instance"):
            cls.instance = super(SwSteering, cls).__new__(cls)
        return cls.instance

    @property
    def name(self) -> str:
        return self.__class__.__name__

    @property
    def ctx(self) -> int:
        return 1

    def set_parse_graph(self):
        """in charge of estimating supported parsing nodes, and latency implications"""
        self.supported_keys = []  # TODO
        self.parser_latency = 100

    def _validate_table(self, table: Table):
        # TODO - everything is permitted in slow path?
        pass

    def latency_eval(self, table: Table) -> LatencyPdf:
        if isinstance(table, Condition):
            return [(self.base_latency, 1)]

        latency_list: LatencyPdf = []
        remaining_prob = 1.0
        for (action, prob) in table.action_iterator:
            base_actions = action.primitives
            (latency, _, _, _) = eval_entry_cost(self, table.keys, base_actions)
            remaining_prob -= prob
            latencies_list_add_item(latency_list, latency, prob)

        return latency_list

    def get_inter_packet_gap(self, packet_latency_pdf: LatencyPdf) -> NanoSec:
        average_lat = 0.0
        for l, p in packet_latency_pdf:
            average_lat += l * p
        return int(average_lat / self.arm_cores)

    def get_memory_footprint(self, table: Table) -> Bytes:
        memory_foorprint = 0
        # On dRMT devices, the memory can be dynamically allocated
        assert table.current_size != None, f"The current size of table {table.name} was not set."
        allocated_entries = (
            math.ceil(table.current_size / YamlConfig.SW_TABLE_SIZE_STEP) * YamlConfig.SW_TABLE_SIZE_STEP
        )

        for (action, prob) in table.action_iterator:
            base_actions = action.primitives
            (_, entry_memory_footprint, _, _) = eval_entry_cost(self, table.keys, base_actions)

            memory_foorprint += float(entry_memory_footprint) * prob

        return int(memory_foorprint * allocated_entries)

    def get_mitigation_latency(self, next_target: TargetBase) -> NanoSec:
        return get_mitigation_cost(self, next_target)


class SmartNic(MultiTargetBase):
    """Defines Smart Nic target"""

    def __init__(self):
        subtargets = {DeviceTargetType.HW_STEERING: HwSteering(), DeviceTargetType.SW_STEERING: SwSteering()}
        super().__init__(name="SmartNic", subtargets=subtargets)

    @property
    def name(self) -> str:
        return self.__class__.__name__

    @property
    def subtargets(self) -> Dict[DeviceTargetType, TargetBase]:
        return self._subtargets

    @property
    def subtarget_names(self) -> List[str]:
        return [target.name for target in self.subtargets.values()]

    @property
    def subtarget_types(self) -> List[DeviceTargetType]:
        return [k for k, v in self.subtargets.items()]

    def get_subtarget_cxt(self, subtarget_type: DeviceTargetType) -> int:
        return self.subtargets[subtarget_type].ctx
