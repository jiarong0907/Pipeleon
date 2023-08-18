from copy import deepcopy
import random
import string
import os, sys
from typing import Any, Dict, List, Optional, Tuple, Union
from ir.condition import Condition
from ir.ir_node import IrNode

import mock_import
from runtime_CLI import RuntimeAPI
from graph_optimizer.json_manager import JsonManager, JsonPlanner
from graph_optimizer.pipelet import Pipelet
from graph_optimizer.graph_optimizer import Optimizer
from graph_optimizer.algorithms import PipeletOptimizer
from graph_optimizer.options import AggregatedOption, ProgramOption, SegmentOptimizationOption

from commons.constants import (
    TOTAL_ENTRY_INSERTION,
    TOTAL_MEMORY,
    DeviceTargetType,
    OptimizeMethod,
    OptimizeTarget,
    OptimizedType,
)
from graph_optimizer.runtime_states import ActionMeta, CondCountProfile, TableCountProfile, RuntimeStates
from commons import types
from ir.irgraph_pipe import IrGraphPipe
from graph_optimizer.options import PipeletOption, ProgramOption
from targets.smart_nic import SmartNic
from ir.action import Action, ActionPrimitive, ActionRuntimeDataItem
from ir.table import NextTableSelector, Table
from ir.action_parameter import FieldParam, RuntimeDataParam
from ir.irgraph import IrGraph
from ir.match_key import MatchKey, MatchType


GLOBAL_ACTION_ID = 0
GLOBAL_TABLE_ID = 0

header_field_pool = [
    "ether.dstAddr",
    "ether.srcAddr",
    "ether.etherType",
    "ipv4.protocol",
    "ipv4.srcAddr",
    "ipv4.dstAddr",
    "tcp.srcPort",
    "tcp.dstPort",
    "tcp.window",
]

mask_pool = [
    0x0000000F,
    0x000000FF,
    0x00000FFF,
    0x0000FFFF,
]


def _create_action(is_base_action: bool, action_name: str, action_id: int) -> Action:
    runtime_data: List[ActionRuntimeDataItem] = []
    primitives: List[ActionPrimitive] = []

    if not is_base_action:
        """
        parameters = [
            {
                "type" : "field",
                "value" : ["migration", "tabl1_data"]
            },
            {
                "type" : "runtime_data",
                "value" : 0
            }
        ]
        """
        letters = string.ascii_lowercase
        # param1 = FieldParam(value=["migration", "tabl1_data"])
        param1 = FieldParam(value=["".join(random.choices(letters, k=10)), "tabl1_data"])
        param2 = RuntimeDataParam(value=0)
        primitive = ActionPrimitive(op="assign", parameters=[param1, param2])
        primitives.append(primitive)

    return Action(action_name, action_id, runtime_data, primitives)


def create_actions(
    num_actions: int,
) -> List[Action]:
    global GLOBAL_ACTION_ID
    iractions = []
    for i in range(num_actions):
        action_type = random.choice([True, False])
        action_name = f"action{GLOBAL_ACTION_ID}"
        action_id = GLOBAL_ACTION_ID
        iractions.append(_create_action(action_type, action_name, action_id))
        GLOBAL_ACTION_ID += 1

    return iractions


def _create_match_keys(num_keys: int, match_type: MatchType) -> List[MatchKey]:
    irkeys = []

    assert num_keys <= len(header_field_pool), f"The header field pool does not have enough match keys."

    header_fields = random.sample(header_field_pool, num_keys)
    for f in header_fields:
        mask = None
        if match_type in [MatchType.LPM, MatchType.TERNARY]:
            mask = random.choice(mask_pool)
        irkeys.append(MatchKey(f, match_type, mask, "hdr." + f))
    return irkeys


def create_table(irgraph: IrGraph, table_name: str, num_keys: int, num_actions: int, match_type: MatchType) -> Table:
    match_keys = _create_match_keys(num_keys, match_type)
    actions = create_actions(num_actions)
    default_action = actions[0]
    default_action_const = True
    default_action_param = []
    default_action_entry_const = True
    max_size = 1024
    p4cjson_description = {}

    for a in actions:
        irgraph.add_action_from_obj(a)
    # irgraph.add_action_from_obj(default_action)

    next_table_selector = NextTableSelector(next_tables={act.name: None for act in actions}, base_default_next=None)

    ir_table = Table(
        irgraph=irgraph,
        id=irgraph.next_table_id(),
        name=table_name,
        keys=match_keys,
        action_ids=[a.id for a in actions],
        default_action_id=default_action.id,
        default_action_const=default_action_const,
        default_action_param=default_action_param,
        default_action_entry_const=default_action_entry_const,
        max_size=max_size,
        p4cjson_description=p4cjson_description,
        next_table_selector=next_table_selector,
    )
    return ir_table


def _connect_two_tables(table1: Table, table2: Table) -> None:
    next_table_name = table2.name
    first_table_action_names = table1.action_names

    next_tables: Dict[str, str] = {an: next_table_name for an in first_table_action_names}
    base_default_next: str = table2.name

    table1._next_table_selector = NextTableSelector(next_tables, base_default_next)
    table1._next_table_selector.set_cur_table(table1)


def create_pipelet(num_tables: int, match_type: MatchType) -> Pipelet:
    global GLOBAL_TABLE_ID
    irgraph = IrGraph(
        target_p4cir_desc={
            "pipelines": [],
            "actions": [],
            "counter_arrays": [],
            "calculations": [],
            "headers": [],
            "header_types": [],
            "header_stacks": [],
        }
    )

    tables: List[Table] = []
    for _ in range(num_tables):
        table_name = f"table{GLOBAL_TABLE_ID}"
        num_keys = 3
        num_actions = 3
        tab = create_table(
            irgraph=irgraph, table_name=table_name, num_keys=num_keys, num_actions=num_actions, match_type=match_type
        )
        tab.target_type = DeviceTargetType.HW_STEERING
        tables.append(tab)
        GLOBAL_TABLE_ID += 1

    # Connect tables to a straight line
    for i in range(num_tables - 1):
        _connect_two_tables(tables[i], tables[i + 1])

    # Create an IrGraphPipe
    irpipe = IrGraphPipe(ancor_point="ingress", target=None)
    irpipe.add_edge(irpipe.root, tables[0], probability=1)
    for i in range(0, len(tables) - 1):
        irpipe.add_edge(tables[i], tables[i + 1], probability=1)
    irpipe.add_edge(tables[-1], irpipe.sink, probability=1)
    irpipe.ir_graph = irgraph
    irpipe.validate()

    irgraph._ir_pipelines.append(irpipe)

    # Get pipelets
    pipelets = JsonPlanner.get_pipelets(irpipe)
    assert len(pipelets) == 1, f"There should be only one pipelet."
    return pipelets[0]


def create_pipelet_asic_static_small(num_tables: int, match_type: MatchType) -> Pipelet:
    pipelet = create_pipelet(num_tables, match_type)
    tables = pipelet.tables
    set_table_target_types(tables, [0] * num_tables)
    set_table_optimized_types(tables, [0] * num_tables)
    set_table_current_sizes(tables, [1] * num_tables)
    set_table_insertion_rates(tables, [1] * num_tables)
    pipelet.irgraph_pipe.target = SmartNic()
    return pipelet


def set_table_target_types(tables: List[Table], targets: List[int]) -> None:
    assert len(tables) == len(targets), f"The number of tables is not the same as the number of targets!"
    for i in range(len(tables)):
        tables[i].target_type = DeviceTargetType(targets[i])


def set_table_optimized_types(tables: List[Table], types: List[int]) -> None:
    assert len(tables) == len(types), f"The number of tables is not the same as the number of targets!"
    for i in range(len(tables)):
        tables[i].optimized_type = OptimizedType(types[i])


def set_table_current_sizes(tables: List[Table], sizes: List[int]) -> None:
    assert len(tables) == len(sizes), f"The number of tables is not the same as the number of sizes!"
    for i in range(len(tables)):
        tables[i].current_size = sizes[i]


def set_table_insertion_rates(tables: List[Table], rates: List[int]) -> None:
    assert len(tables) == len(rates), f"The number of tables is not the same as the number of rates!"
    for i in range(len(tables)):
        tables[i].entry_insertion_rate = rates[i]


def set_pipelet_option_gain_cost(
    pipelet_option: PipeletOption, mcost: int, icost: int, lgain: float, tgain: float
) -> None:
    pipelet_option.mcost = mcost
    pipelet_option.icost = icost
    pipelet_option.lgain = lgain
    pipelet_option.tgain = tgain


def _call_optimizer(
    irg: IrGraph, enabled_methods: List[OptimizeMethod], optimize_target: OptimizeTarget
) -> Optional[ProgramOption]:
    """A wrapper to call the reoptimize function and get returned ProgramOption"""
    ingress_graph = irg.get_pipe("ingress")
    json_manager = JsonManager(api=RuntimeAPI())
    runtime_states = json_manager.retrieve_runtime_states(f"{round}_presplit_preopt.json")
    optimizer = Optimizer(api=RuntimeAPI(), sampling_period_us=1000000)
    optimizer._update_pipeline_stats(irg, runtime_states)

    mtotal: types.Bytes = runtime_states.total_memory
    itotal: int = runtime_states.total_entry_insertion_bandwidth
    pipelets = JsonPlanner.get_pipelets(ingress_graph)

    # assert len(pipelets) == 1
    program_option = PipeletOptimizer.reoptimize_dp(
        mavail=mtotal,
        iavail=itotal,
        optimize_method=enabled_methods,
        optimize_target=optimize_target,
        pipelets=pipelets,
    )
    return program_option


def _gen_count_profile_reorder(tab: Table, drop_pkt_count: int, total_pkt: int) -> TableCountProfile:
    """Generate fake TableCountProfile for reordering test

    tab: The table to generate the profile
    drop_pkt_count: counter value for the action with drop
    total_pkt: Sum of the counter values of all actions
    """
    tab_name = tab.name
    num_actions = len(tab.action_ids)
    counts = dict()
    action_meta = dict()
    for action_id in tab.action_ids:
        action = tab.irgraph.action_id_to_action[action_id]

        if len(action.primitives) > 0 and action.primitives[0].op == "mark_to_drop":
            counts[action_id] = drop_pkt_count
        else:
            if num_actions == 1:
                counts[action_id] = total_pkt - drop_pkt_count
            else:
                counts[action_id] = (total_pkt - drop_pkt_count) // (num_actions - 1)
        act_meta = ActionMeta(
            action_name=tab.action_id_to_name[action_id],
            action_id=action_id,
        )
        act_meta.set_table_info(tab_name)
        action_meta[action_id] = act_meta
    return TableCountProfile(counts=counts, action_meta=action_meta, drop_count=drop_pkt_count)


def _gen_count_profile_even(node: IrNode) -> Union[TableCountProfile, CondCountProfile]:
    """Generate fake TableCountProfile/CondCountProfile for non-reorder test.
    It sets the same counter value for each action/branch of a table/condition
    """
    COUNT_VALUE = 1000
    if isinstance(node, Table):
        tab: Table = node
        tab_name = tab.name
        num_actions = len(tab.action_ids)
        counts = dict()
        action_meta = dict()
        for action_id in tab.action_ids:
            counts[action_id] = COUNT_VALUE
            act_meta = ActionMeta(
                action_name=tab.action_id_to_name[action_id],
                action_id=action_id,
            )
            act_meta.set_table_info(tab_name)
            action_meta[action_id] = act_meta
        drop_count = 0
        return TableCountProfile(counts=counts, action_meta=action_meta, drop_count=drop_count)
    elif isinstance(node, Condition):
        return CondCountProfile(
            counts={
                "true": COUNT_VALUE,
                "false": COUNT_VALUE,
            }
        )
    else:
        raise Exception(
            f"Unsupported node type. We only support Table or Condition but we" f" got {node.__class__.__name__}"
        )


def _is_drop_action(action: Action) -> bool:
    primitives = action.primitives
    for prim in primitives:
        if prim.op == "mark_to_drop":
            return True
    return False


def _gen_count_profile_random(
    node: IrNode, min_count: int = 200, max_count: int = 300
) -> Union[TableCountProfile, CondCountProfile]:
    """Generate fake random TableCountProfile/CondCountProfile for non-reorder test.
    It sets the same counter value for each action of a table/condition
    """
    if isinstance(node, Table):
        tab: Table = node
        tab_name = tab.name
        num_actions = len(tab.action_ids)
        counts = dict()
        action_meta = dict()
        for i in range(num_actions):
            counts[i] = random.randint(min_count, max_count)
            act_meta = ActionMeta(action_name=tab.action_id_to_name[tab.action_ids[i]], action_id=tab.action_ids[i])
            act_meta.set_table_info(tab_name)
            action_meta[i] = act_meta
            if _is_drop_action(tab.irgraph.action_id_to_action[tab.action_ids[i]]):
                counts[i] = random.randint(min_count, max_count)
        drop_count = 0
        return TableCountProfile(counts=counts, action_meta=action_meta, drop_count=drop_count)
    elif isinstance(node, Condition):
        return CondCountProfile(
            counts={
                "true": random.randint(min_count, max_count),
                "false": random.randint(min_count, max_count),
            }
        )
    else:
        raise Exception(
            f"Unsupported node type. We only support Table or Condition but we" f" got {node.__class__.__name__}"
        )


def gen_runtime_stats(
    tables: List[Table],
    conds: List[Condition],
    even_counter_distr: bool = False,
    drop_rate: float = 0.75,
    min_tab_size: int = 10,
    max_tab_size: int = 20,
    branch_counts: Dict[types.BranchName, int] = {"true": 10, "false": 10},
) -> RuntimeStates:
    """Generate a fake runtime stats for the test purpose"""
    if even_counter_distr:
        table_to_counts = {t.name: _gen_count_profile_even(t) for t in tables}
    else:
        table_to_counts = {t.name: _gen_count_profile_reorder(t, int(10000 * drop_rate), 10000) for t in tables}

    return RuntimeStates(
        table_to_counts=table_to_counts,
        cond_to_counts={c.name: CondCountProfile(counts=deepcopy(branch_counts)) for c in conds},
        table_to_size={t.name: random.randint(min_tab_size, max_tab_size) for t in tables},
        table_to_entry_insertion_count={t.name: 10 for t in tables},
        total_memory=TOTAL_MEMORY,
        total_entry_insertion_bandwidth=TOTAL_ENTRY_INSERTION,
        mapping_dict={"tables": {t.name: {"entries": _gen_entries_json()} for t in tables}},
    )


def gen_runtime_stats_random(
    tables: List[Table], conds: List[Condition], min_count: int = 200, max_count: int = 1000
) -> RuntimeStates:
    """Generate a fake random runtime stats for the test purpose"""
    return RuntimeStates(
        table_to_counts={t.name: _gen_count_profile_random(t, min_count, max_count) for t in tables},
        cond_to_counts={c.name: _gen_count_profile_random(c, min_count, max_count) for c in conds},
        table_to_size={t.name: random.randint(50, 150) for t in tables},
        table_to_entry_insertion_count={t.name: 5 for t in tables},
        total_memory=TOTAL_MEMORY,
        total_entry_insertion_bandwidth=TOTAL_ENTRY_INSERTION,
        mapping_dict={"tables": {t.name: {"entries": _gen_entries_json()} for t in tables}},
    )


def _gen_entries_json() -> List[Dict[str, Any]]:
    return [
        {
            "action_name": "act1",
            "action_data": ["048d", "06"],
            "match_key": [
                {"type": "EXACT", "key": "0a000a01"},
                {
                    "type": "LPM",
                    "key": "0a000a01",
                    "prefix_length": 16,
                },
                {
                    "type": "TERNARY",
                    "key": "0a000a01",
                    "mask": "0000ff00",
                },
                {
                    "type": "VALID",
                    "key": 1,
                },
                {
                    "type": "RANGE",
                    "start": "0000",
                    "end": "0F00",
                },
            ],
            "priority": 100,
        }
    ]


def get_topk_pipelet(all_pipelets: List[Pipelet], topk_pipelet_names: List[types.TableName]) -> List[Pipelet]:
    return [pipelet for pipelet in all_pipelets if pipelet.root.name in topk_pipelet_names]


def apply_pipelet_options(options: List[AggregatedOption], irgraph_pipe: IrGraphPipe):
    """Apply the whole program optimization to a copied graph. Used to
    evaluate the performance gain.
    """
    pipelets_copy = JsonPlanner.get_pipelets(irgraph_pipe)
    root_name_to_pipelet: Dict[types.TableName, Pipelet] = {}
    for pipelet in pipelets_copy:
        root_name_to_pipelet[pipelet.root.name] = pipelet

    for op in options:
        assert isinstance(op, PipeletOption), f"The option is not PipeletOption. Got type{op}"
        JsonPlanner.apply_reordering(root_name_to_pipelet[op.pipelet.root.name], op.new_order)
        # only the reorder option
        if op.combined_options == None:
            return
        for comb_op in op.combined_options:
            if isinstance(comb_op, SegmentOptimizationOption):
                JsonPlanner.apply_segment_opt(root_name_to_pipelet[op.pipelet.root.name], comb_op)
            else:
                raise Exception("Unrecognized optimization option!")


def main():
    create_pipelet(5, MatchType.TERNARY)


if __name__ == "__main__":
    main()
