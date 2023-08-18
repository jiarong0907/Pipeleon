from typing import List, Tuple
import math
from api.driver_api import ParallelExec, Percent
from ir.action import ActionPrimitive
from ir.match_key import MatchKey
from commons.types import Joule, NanoSec
import commons.config as config
import commons.yaml_config as YamlConfig


def have_ternary_key(keys: List[MatchKey]) -> bool:
    for key in keys:
        if key.match_type.value in ["ternary"]:
            return True
    return False


def have_lpm_key(keys: List[MatchKey]) -> bool:
    for key in keys:
        if key.match_type.value in ["lpm"]:
            return True
    return False


def is_cache_action_tracing_prim(prim: ActionPrimitive) -> bool:
    if prim.op == "install_cache_entry":
        return True
    elif prim.op == "push" and prim.parameters[0].value == "$action_data_stack":
        return True
    elif prim.op == "add_header" and "$action_data_stack" in prim.parameters[0].value:
        return True
    elif prim.op == "assign" and "$action_data_stack" in prim.parameters[0].value[0]:
        return True
    elif prim.op == "assign" and "flex_action_path" in prim.parameters[0].value[1]:
        return True

    return False


def get_valid_action_prim_num(action_primitives: List[ActionPrimitive]) -> int:
    """Count the number of primitives before exit and also exclude
    path tracing primitives

    Note: We exclude path tracing primitives, because this is used to emulate
    the software path tracing solution. For real software implementation, the
    overhead would be cache entry insert delay, which will affect the cache hit
    rate. Thus, it can be emulated by lowering down the cache hit rate ratio.
    """
    count = 0
    i = 0
    while i < len(action_primitives):
        act_prim = action_primitives[i]
        # path tracing will add 6 additional primitives
        if is_cache_action_tracing_prim(act_prim):
            i += 1
            continue

        count += 1
        if act_prim.op == "exit":
            break
        i += 1

    return count


class BF2_HW:
    @staticmethod
    def eval_entry_latency_calibrated(keys: List[MatchKey], action_primitives: List[ActionPrimitive]) -> NanoSec:
        assert config.USE_CALIBRATED_COST_MODEL, f"Calibrated model is called when the flag is not enabled"
        assert (
            YamlConfig.HW_LAT_EXACT_COST != -1
            and YamlConfig.HW_LAT_LPM_RATIO != -1
            and YamlConfig.HW_LAT_TERNARY_RATIO != -1
            and YamlConfig.HW_LAT_MATCH_BASE != -1
            and YamlConfig.HW_LAT_ACTION_COST != -1
            and YamlConfig.HW_LAT_ACTION_BASE != -1
        ), f"Calibrated model parameter is not set"

        match_key_lat = YamlConfig.HW_LAT_EXACT_COST
        if have_ternary_key(keys):
            match_key_lat *= YamlConfig.HW_LAT_TERNARY_RATIO
        elif have_lpm_key(keys):
            match_key_lat *= YamlConfig.HW_LAT_LPM_RATIO

        action_prim_len = get_valid_action_prim_num(action_primitives)
        action_lat = action_prim_len * YamlConfig.HW_LAT_ACTION_COST

        return match_key_lat + action_lat

    @staticmethod
    def eval_entry_latency(keys: List[MatchKey], action_primitives: List[ActionPrimitive]) -> NanoSec:
        if config.USE_CALIBRATED_COST_MODEL:
            return BF2_HW.eval_entry_latency_calibrated(keys, action_primitives)

        latency = YamlConfig.DRAM_LATENCY
        if have_ternary_key(keys):
            latency *= YamlConfig.HW_LAT_TERNARY_RATIO
        elif have_lpm_key(keys):
            latency *= YamlConfig.HW_LAT_LPM_RATIO

        action_prim_len = get_valid_action_prim_num(action_primitives)

        if action_prim_len > YamlConfig.HW_ACTION_LEN_STEP:
            latency *= math.ceil(float(action_prim_len) / YamlConfig.HW_ACTION_LEN_STEP)

        return latency

    @staticmethod
    def entry_memory_footprint(keys: List[MatchKey], action_primitives: List[ActionPrimitive]):
        entry_size = YamlConfig.HW_ENTRY_SIZE
        length = max(len(keys), len(action_primitives))

        if have_ternary_key(keys):
            entry_size *= YamlConfig.HW_LAT_TERNARY_RATIO
        elif have_lpm_key(keys):
            entry_size *= YamlConfig.HW_LAT_LPM_RATIO

        if length > YamlConfig.HW_MEM_LEN_STEP:
            entry_size *= math.ceil(float(length) / YamlConfig.HW_MEM_LEN_STEP)

        return entry_size

    @staticmethod
    def eval_entry_cost(
        keys: List[MatchKey], action_primitives: List[ActionPrimitive]
    ) -> Tuple[NanoSec, Percent, Joule, ParallelExec]:
        latency = BF2_HW.eval_entry_latency(keys, action_primitives)
        memory_usage = BF2_HW.entry_memory_footprint(keys, action_primitives)

        return (latency, memory_usage, None, None)


class BF2_SW:
    @staticmethod
    def eval_entry_latency(keys: List[MatchKey], action_primitives: List[ActionPrimitive]) -> NanoSec:
        latency = YamlConfig.DRAM_LATENCY

        if have_ternary_key(keys):
            latency *= 2
        elif have_lpm_key(keys):
            latency *= 2

        latency += YamlConfig.CPU_LATENCY

        return latency

    @staticmethod
    def entry_memory_footprint(keys: List[MatchKey], action_primitives: List[ActionPrimitive]) -> int:
        entry_size = YamlConfig.SW_ENTRY_SIZE
        length = max(len(keys), len(action_primitives))

        if length > YamlConfig.SW_MEM_LEN_STEP:
            entry_size *= math.ceil(float(length) / YamlConfig.SW_MEM_LEN_STEP)

        return entry_size

    @staticmethod
    def eval_entry_cost(
        keys: List[MatchKey], action_primitives: List[ActionPrimitive]
    ) -> Tuple[NanoSec, Percent, Joule, ParallelExec]:
        latency = BF2_SW.eval_entry_latency(keys, action_primitives)
        memory_footprint = BF2_SW.entry_memory_footprint(keys, action_primitives)
        return (latency, memory_footprint, None, None)
