"""
Downstream API:
Defines the requirement for vedor specific target driver implementation
"""
from numpy import isin
from typing import Dict, List, Tuple

from ir.action import ActionPrimitive
from ir.match_key import MatchKey
from targets.driver_api_implementation import BF2_HW, BF2_SW
import commons.yaml_config as YamlConfig

OpequePointer = int
Name = str
TargetHandle = OpequePointer
SubtargetHandle = OpequePointer
TableHandle = OpequePointer
Percent = float
Joule = float
NanoSec = int
ParallelExec = int
InsertionCostPerSubtarget = None  # Dict[Name,NanoSec,ParallelExec]
TableId = int


def get_target_handle() -> TargetHandle:
    """
    returns am opeque device handle
    """
    pass


def get_subtargets(target: TargetHandle) -> List[Tuple[str, TargetHandle]]:
    """
    return list on nested targets in device.
    this will allow the compiler to
    """
    pass


def get_mitigation_cost(sender_subtarget, reciver_subtarget) -> NanoSec:

    if not sender_subtarget.name in ["SwSteering", "HwSteering"] or not reciver_subtarget.name in [
        "SwSteering",
        "HwSteering",
    ]:
        raise TypeError(f"unknown mitigation cost form {sender_subtarget.name} to {reciver_subtarget.name}")

    if sender_subtarget.name == reciver_subtarget.name:
        return 0

    return YamlConfig.CROSS_TARGET_MIGRATION_COST


"""
params:
    - subtarget: the subtarget where the entry exists, HWSteering or SwSteering
    - keys: List of the match keys of the entry.
"""


def eval_entry_cost(
    subtarget, keys: List[MatchKey], action_primitives: List[ActionPrimitive]
) -> Tuple[NanoSec, Percent, Joule, ParallelExec]:
    if subtarget.name == "SwSteering":
        return BF2_SW.eval_entry_cost(keys, action_primitives)
    if subtarget.name == "HwSteering":
        return BF2_HW.eval_entry_cost(keys, action_primitives)
    else:
        raise TypeError(f"unknown entry cost for {subtarget} subtarget")


def eval_conditional_statment_cost(subtarget, condition, action_list) -> Tuple[NanoSec, Percent, Joule, ParallelExec]:
    """
    return expected latency, memory utilization, energy, and parallel execution capacity for the rule
    """
    pass


def eval_statfull_entry_state_change(
    subtarget, flow_definition, num_states, time_resolution, action_list
) -> Tuple[NanoSec, Percent, Joule, ParallelExec]:
    """
    # TODO statefull API AI OMER.
    return expected latency, memory utilization, energy, and parallel execution capacity for the rule
    """
    pass


def eval_entry_insertion_cost(subtarget, key_type, action_list) -> InsertionCostPerSubtarget:
    """
    return expected latency and parallel execution capacity for the rule, per target.
    example: NIC hw subtarget may require arm core resources to handle insertion.
    those resources might hurt SW steering performance.

    Matty: ignore cpu cross entrophy for insertion
    """
    pass


def deploy_pipe_to_subtarget(subtarget, pipe) -> Dict[TableId, TableHandle]:
    pass


def get_counters(subtarget_handle, query_handle):
    """
    collect runtime info from device:
        1. entires insertion
        2. entires removal
        3. table / action / entry hit statistics
        4. actual cost (latency, etc...)
    """
    pass


def add_entry():
    pass


def remove_entry():
    pass
