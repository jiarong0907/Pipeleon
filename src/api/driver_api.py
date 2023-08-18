"""
Downstream API:
Defines the requirement for vedor specific target driver implementation
"""
from typing import Dict, List, Tuple

OpequePointer = int
Name = str
TargetHandle = OpequePointer
SubtargetHandle = OpequePointer
TableHandle = OpequePointer
Percent = float
Joule = float
NanoSec = int
ParallelExec = int
InsertionCostPerSubtarget = Dict[Name, Tuple[NanoSec, ParallelExec]]
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


def get_mitigation_cost(sender_subtarget, reciver_subtarget) -> (NanoSec, NanoSec):
    """
    returns the mitigation cost between sub targets in target (per device)
    """
    pass


def eval_entry_cost(subtarget, key_type, action_list) -> (NanoSec, Percent, Joule, ParallelExec):
    """
    return expected latency, memory utilization, energy, and parallel execution capacity for the rule
    """
    pass


def eval_conditional_statment_cost(subtarget, condition, action_list) -> (NanoSec, Percent, Joule, ParallelExec):
    """
    return expected latency, memory utilization, energy, and parallel execution capacity for the rule
    """
    pass


def eval_statfull_entry_state_change(
    subtarget, flow_definition, num_states, time_resolution, action_list
) -> (NanoSec, Percent, Joule, ParallelExec):
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
