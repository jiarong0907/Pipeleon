from __future__ import annotations
from copy import deepcopy
import math
from graph_optimizer.metadata import GroupCacheMetadata
from ir.next_table_selector import NextTableSelector
from ir.opt_table import CacheTable
from ir.table_entry_builder import GroupCacheTableEntryBuilder
import shutil
from dataclasses import dataclass
import itertools
from functools import reduce
import operator
import os
import pickle
from typing import Dict, Iterator, List, Set, Tuple, Union
import networkx as nx
import commons.config as config

from ir.action_parameter import (
    PARAMTYPE,
    ActionParam,
    CalculationParam,
    ExpressionBody,
    ExpressionParam,
    FieldParam,
    HeaderParam,
    HexStrParam,
    RuntimeDataParam,
)

from ir.match_key import MatchType, MatchKey
from ir.action import Action, ActionPrimitive, ActionRuntimeDataItem, ConditionAction, OptAction
from commons.types import ActionName, Probability, TableId, TableName
from commons.base_logging import logger
from commons.constants import DeviceTargetType
from graph_optimizer.data_access_info import DataAccessInfo

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ir.irgraph import IrGraph
    from ir.table import Table
    from ir.action import GeneralAction
    from graph_optimizer.pipelet import Pipelet
    from ir.irgraph_pipe import IrGraphPipe
    from ir.ir_node import Sink
    from ir.condition import Condition


class OptUtils:
    @classmethod
    def _extract_action_data_write(cls, action: GeneralAction) -> List[ActionParam]:
        """Extract action parameters written by an action"""
        write_list: List[ActionParam] = []
        for primitive in action.primitives:
            op = primitive.op
            # The following types are extracted from switch.p4
            # field operation
            if op in ["assign", "modify_field_rng_uniform", "modify_field_with_hash_based_offset"]:
                lhs = primitive.parameters[0]
                assert lhs.type == PARAMTYPE.FIELD, f"The left hand side of assign must be field, but we got {lhs.type}"
                write_list.append(lhs)
            # header operation
            elif op in ["add_header", "remove_header", "assign_header"]:
                lhs = primitive.parameters[0]
                assert lhs.type == PARAMTYPE.HEADER, f"The left hand side of {op} must be header, but we got {lhs.type}"
                write_list.append(lhs)
            # clone operation, their session id
            elif op in ["clone_egress_pkt_to_egress", "clone_ingress_pkt_to_egress", "generate_digest"]:
                lhs = primitive.parameters[0]
                # they are constants
                if lhs.type == PARAMTYPE.RUNTIME_DATA or lhs.type == PARAMTYPE.HEX_STR:
                    continue
                if lhs.type == PARAMTYPE.FIELD:
                    write_list.append(lhs)
                else:
                    raise Exception("Unexpected lhs type")
            # drop operation
            elif op == "drop":
                continue
            # counter could be added by the profiler
            elif op == "count":
                continue
            # push could be added for cached tables
            elif op == "push":
                assert primitive.parameters[0].value == "$action_data_stack", f"push is not used for cache path tracing"
                continue
            # do not support stateful processing
            elif op == "execute_meter":
                raise Exception("Unsupported op {op} for dependency analysis")
        return write_list

    @classmethod
    def _extract_action_data_read(cls, irg: IrGraph, action: GeneralAction) -> List[ActionParam]:
        """Extract action parameters read by an action"""
        read_list: List[ActionParam] = []
        for primitive in action.primitives:
            op = primitive.op
            # The following types are extracted from switch.p4
            # field operation
            if op == "assign":
                rhs = primitive.parameters[1]
                assert len(primitive.parameters) == 2, f"Assign op should have only two parameters"
                # we don't care about constants
                if isinstance(rhs, RuntimeDataParam) or isinstance(rhs, HexStrParam):
                    continue
                elif isinstance(rhs, FieldParam):
                    read_list.append(rhs)
                elif isinstance(rhs, ExpressionParam):
                    read_list += rhs._get_variables(irg)
                else:
                    raise Exception("Unexpected parameter instance for assign op")
            elif op == "modify_field_with_hash_based_offset":
                for i in range(1, len(primitive.parameters)):
                    param = primitive.parameters[i]
                    if isinstance(param, RuntimeDataParam) or isinstance(param, HexStrParam):
                        continue
                    elif isinstance(param, FieldParam):
                        read_list.append(param)
                    elif isinstance(param, CalculationParam):
                        read_list += param._get_variables(irg)
                    else:
                        raise Exception(f"Unexpected parameter instance for " f"modify_field_with_hash_based_offset")
            elif op == "modify_field_rng_uniform":
                for i in range(1, len(primitive.parameters)):
                    param = primitive.parameters[i]
                    if isinstance(param, RuntimeDataParam) or isinstance(param, HexStrParam):
                        continue
                    elif isinstance(param, FieldParam):
                        read_list.append(param)
                    else:
                        raise Exception(f"Unexpected parameter instance for modify_field_rng_uniform")
            # header operation
            elif op in ["add_header", "remove_header"]:
                rhs = primitive.parameters[0]
                assert (
                    rhs.type == PARAMTYPE.HEADER
                ), f"The right hand side of {op} must be header, but we got {rhs.type}"
                read_list.append(rhs)
            elif op in ["assign_header"]:
                rhs = primitive.parameters[1]
                assert (
                    rhs.type == PARAMTYPE.HEADER
                ), f"The right hand side of {op} must be header, but we got {rhs.type}"
                read_list.append(rhs)
            # clone operation, their session id
            elif op in ["clone_egress_pkt_to_egress", "clone_ingress_pkt_to_egress", "generate_digest"]:
                for i in range(1, len(primitive.parameters)):
                    param = primitive.parameters[i]
                    if isinstance(param, RuntimeDataParam) or isinstance(param, HexStrParam):
                        continue
                    elif isinstance(param, FieldParam):
                        read_list.append(param)
                    else:
                        raise Exception(
                            f"Unexpected parameter instance for clone_egress_pkt_to_egress, "
                            f"clone_ingress_pkt_to_egress, and generate_digest"
                        )
            # drop operation
            elif op == "drop":
                continue
            # counter could be added by the profiler
            elif op == "count":
                continue
            # push could be added for cached tables
            elif op == "push":
                assert primitive.parameters[0].value == "$action_data_stack", f"push is not used for cache path tracing"
                continue
            # do not support stateful processing
            elif op == "execute_meter":
                raise Exception(f"Unsupported op {op} for dependency analysis")

        return read_list

    @classmethod
    def _check_entry_insertion(cls, action: GeneralAction) -> bool:
        """Check whether the action install a new table entry.
        If so, it cannot be reordered
        """
        for primitive in action.primitives:
            op = primitive.op
            # We need to add more whenever we have a new insert AIP
            if op == "install_exact_entry_1_0":
                return True
        return False

    @classmethod
    def _check_expression_mergeable(cls, expr: ExpressionParam) -> bool:
        """Check whether an expression can be merged in a PipeletGroup
        - The outest op must be d2b or == or &&
        - The left must be FieldParam
        - The right must be HexStrParam
        """
        assert isinstance(expr.value, ExpressionBody)
        if expr.value.op == "and":
            assert isinstance(expr.value.left, ExpressionParam)
            assert isinstance(expr.value.right, ExpressionParam)
            return cls._check_expression_mergeable(expr.value.left) and cls._check_expression_mergeable(
                expr.value.right
            )

        if not (expr.value.op == "d2b" or expr.value.op == "=="):
            return False
        if not isinstance(expr.value.left, FieldParam):
            return False
        if not isinstance(expr.value.right, HexStrParam):
            return False
        return True

    @classmethod
    def _check_condition_mergeable(cls, cond: Condition) -> bool:
        """Check whether a condition can be merged in a PipeletGroup
        - The outest op must be d2b or == or &&
        - The left must be FieldParam
        - The right must be HexStrParam
        # TODO: how to handle isValid? !isValid has the same expression json
        """
        return cls._check_expression_mergeable(cond.expression)

    @classmethod
    def _extract_condition_read(cls, irg: IrGraph, cond: Condition) -> List[ActionParam]:
        """Extract action parameters read by a condition. Used to generate cache keys."""
        return cond.expression._get_variables(irg)

    @classmethod
    def _extract_condition_match_key(cls, irg: IrGraph, cond: Condition) -> Set[MatchKey]:
        """Extract action parameters read by a condition"""
        act_params = cls._extract_condition_read(irg, cond)
        mkeys: List[MatchKey] = []
        for act_param in act_params:
            assert isinstance(act_param, FieldParam), (
                f"Only support converting FieldParam to match key, but " f"got {type(act_param)}"
            )
            mkeys.append(cls._field_param_to_match_key(act_param))
        if len(mkeys) != len(set(mkeys)):
            logger.warning(f"There are duplicated match keys in this condition, please double check.")
        return set(mkeys)

    @classmethod
    def _extract_data_access_info(cls, irg: IrGraph, tab: Table) -> DataAccessInfo:
        """Extract variables accessed by a table, including match keys (read),
        variables read by actions (rhs), and variables written by actions(lhs).
        """
        match_keys = tab.keys
        read: List[ActionParam] = []
        write: List[ActionParam] = []
        actions: List[GeneralAction] = [a for (a, _) in tab.action_iterator]
        entry_insert = False

        for a in actions:
            read += cls._extract_action_data_read(irg, a)
            write += cls._extract_action_data_write(a)
            entry_insert |= cls._check_entry_insertion(a)

        return DataAccessInfo(
            match_key=match_keys, action_read=read, action_write=write, has_entry_insertion=entry_insert
        )

    @classmethod
    def _get_match_keys_from_header(cls, irg: IrGraph, header: HeaderParam) -> List[MatchKey]:
        """A helper function which generates match keys of all fields in the given header"""
        header_name = header.value
        all_headers = irg.headers
        hdr_id = -1
        for h in all_headers:
            if h.name == header_name:
                hdr_id = h.id
        assert hdr_id != -1, f"Header {header_name} was not found in irgraph headers."

        match_keys: List[MatchKey] = []
        all_header_types = irg.header_types
        for ht in all_header_types:
            if ht.id == hdr_id:
                for f in ht.fields:
                    match_keys.append(
                        MatchKey(
                            header=f"{header_name}.{f.name}",
                            match_type=MatchType.EXACT,
                            global_mask=None,
                            name=f"hdr.{header_name}.{f.name}",
                        )
                    )
                break
        return match_keys

    @classmethod
    def _field_param_to_match_key(cls, field: FieldParam) -> MatchKey:
        header = ".".join(field.value)
        if field.value[0] == "scalars":
            name = "meta." + field.value[1].split(".")[1]
        elif field.value[0] == "standard_metadata":
            name = header
        else:
            name = "hdr." + header
        return MatchKey(header=header, match_type=MatchType.EXACT, global_mask=None, name=name)

    @classmethod
    def _data_access_info_to_match_key(cls, irg: IrGraph, info: DataAccessInfo) -> Set[MatchKey]:
        res_keys: Set[MatchKey] = set()

        match_keys = info.match_key
        action_read = info.action_read
        for mkey in match_keys:
            # if mkey.header not in data_with_strict_match_dep:
            res_keys.add(mkey)
        for a in action_read:
            if isinstance(a, FieldParam):
                res_keys.add(cls._field_param_to_match_key(a))
            elif isinstance(a, HeaderParam):
                # if a header is read, all its keys will be added as cache keys
                res_keys = res_keys.union(set(cls._get_match_keys_from_header(irg, a)))
            else:
                TypeError(f"Unexpected type: {type(a)}.")

        return res_keys

    @classmethod
    def _has_match_dependency(cls, irg: IrGraph, tab1: Table, tab2: Table) -> bool:
        """Check whether tab1 has match dependency with tab2.

        Tab1 has match dependency with tab2 means that tab1's actions change the
        header fields or metadata used by tab2 as match keys.
        """
        data_info1 = cls._extract_data_access_info(irg, tab1)
        data_info2 = cls._extract_data_access_info(irg, tab2)
        return data_info2._match_key_written_by_other(data_info1)

    @classmethod
    def _can_swap_order(cls, irg: IrGraph, tab1: Table, tab2: Table) -> bool:
        """Check whether we can swap the order of tab1 and tab2 without voliating their dependency"""
        data_info1 = cls._extract_data_access_info(irg, tab1)
        data_info2 = cls._extract_data_access_info(irg, tab2)

        return not data_info1._has_dependency_with(data_info2)

    @classmethod
    def _can_merge(cls, irg: IrGraph, tab1: Table, tab2: Table) -> bool:
        """Check whether the two tables can be merged.

        Cases that cannot be merged:
            (1) tab1 write the match key of tab2
        """

        data_info1 = cls._extract_data_access_info(irg, tab1)
        data_info2 = cls._extract_data_access_info(irg, tab2)

        """Check (1) tab1 write the match key of tab2
        """
        return not data_info2._match_key_written_by_other(data_info1)

    @classmethod
    def _can_cache(cls, irg: IrGraph, tables: List[Table]) -> bool:
        """Check whether a list of tables can be cached.

        Cases that cannot be cached:
            (1) tab1 write the match key of tab2
        """
        for i in range(0, len(tables) - 1):
            for j in range(1, len(tables)):
                data_info1 = cls._extract_data_access_info(irg, tables[i])
                data_info2 = cls._extract_data_access_info(irg, tables[j])
                """Check (1) tab1 write the match key of tab2
                """
                if data_info2._match_key_written_by_other(data_info1):
                    return False
        return True

    @classmethod
    def _topo_sort(cls, irg: IrGraph, pipelet: Pipelet) -> Iterator[List[TableId]]:
        """Return all reorder plans following the dependency relations."""
        tables = pipelet.tables
        id_to_table = {}
        for i in range(len(tables)):
            id_to_table[i] = tables[i]

        # Build a depdency graph
        dag = nx.DiGraph(directed=True)
        dag.add_nodes_from([(key, {"name": value.name, "original_pos": key}) for key, value in id_to_table.items()])
        for i in range(len(tables) - 1):
            for j in range(i + 1, len(tables)):
                if not cls._can_swap_order(irg, tables[i], tables[j]):
                    dag.add_edges_from([(i, j)])

        return nx.all_topological_sorts(dag)

    @classmethod
    def _check_strict_match_dependency(cls, access_infos: List[DataAccessInfo]) -> Set[str]:
        """Check the strict match dependency between multiple DataAccessInfo object.
        If field is written before all its read, this field can be removed from the cache
        key. We call this dependency strict match dependency (Inspired by B-Cache:
        https://pages.cs.wisc.edu/~zijun/BCache.pdf).

        This function will return a set of fields that can be removed from the cache key.
        For HeaderParam, the returned value is header name, e.g., ipv4. For FieldParam, the
        returned value is '.'.join(value), e.g., ipv4.srcAddr.
        """
        has_been_read: Set[str] = set()  # to record the read fields so far
        strict_match_dep: Set[str] = set()  # to record the fields that can be removed from the cache key
        for info in access_infos:
            match_keys = info.match_key
            action_read = info.action_read
            action_write = info.action_write
            # Match key is read by the table
            for mkey in match_keys:
                has_been_read.add(mkey.header)
            # For action primitives, we only care about field and header.
            # _extract_data_access_info should return only FieldParam and HeaderParam
            for a in action_read:
                if isinstance(a, FieldParam):
                    has_been_read.add(".".join(a.value))
                elif isinstance(a, HeaderParam):
                    has_been_read.add(a.value)
                else:
                    raise TypeError(f"Only FieldParam and HeaderParam are expected, but got {type(a)}")
            for a in action_write:
                if isinstance(a, FieldParam):
                    # The field can be added to the strict match dependency set if
                    # 1) it is not read before
                    # 2) it is not a field of a header that has been read
                    # 3) it is not user-defined metadata, which is always initialized to 0
                    if (
                        ".".join(a.value) not in has_been_read
                        and a.value[0] not in has_been_read
                        and "userMetadata" not in ".".join(a.value)
                    ):
                        strict_match_dep.add(".".join(a.value))
                elif isinstance(a, HeaderParam):
                    # A header can be added to the strict match dependency set if
                    # 1) it is not read before
                    # 2) its fields have not been read
                    if a.value not in has_been_read:
                        partial_read = False  # to check whether its fields have been read
                        for r in has_been_read:
                            if a.value in r:
                                partial_read = True
                                break
                        if not partial_read:
                            strict_match_dep.add(a.value)
                else:
                    raise TypeError(f"Only FieldParam and HeaderParam are expected, but got {type(a)}")

        return strict_match_dep

    @classmethod
    def _create_merge_action(
        cls, irgraph: IrGraph, pro_act: Tuple[Tuple[Action, Probability], ...]
    ) -> Tuple[OptAction, Probability]:
        """Create merged table given the cross-producted action.
        Action runtime data and primitives are directly concatenated.
        Action probability are also cross-product of the merged actions.
        """
        merged_name = "merged_" + "_".join([a.name for a, prob in pro_act])
        merged_prob = reduce(operator.mul, [prob for a, prob in pro_act], 1)
        merged_id = irgraph.next_action_id()
        merged_runtime_data: List[ActionRuntimeDataItem] = list(
            itertools.chain(*[a.runtime_data for a, prob in pro_act])
        )
        merged_primitives: List[ActionPrimitive] = list(itertools.chain(*[a.primitives for a, prob in pro_act]))
        merged_action = OptAction(
            name=merged_name, id=merged_id, runtime_data=merged_runtime_data, primitives=merged_primitives
        )
        for original_action, _ in pro_act:
            merged_action.optimized_from.append(original_action)
            assert isinstance(original_action, Action) or isinstance(original_action, ConditionAction)
            original_action.post_opt_action_counters.append((DeviceTargetType.HW_STEERING, merged_id))
        return (merged_action, merged_prob)

    @classmethod
    def _merge_actions_pipelet(cls, irgraph: IrGraph, tables: List[Table]) -> List[Tuple[OptAction, Probability]]:
        """Merge actions from multiple tables by cross-product for a Pipelet."""
        all_tab_actions: List[List[Tuple[Action, Probability]]] = []
        for tab in tables:
            all_tab_actions.append([(a, prob) for a, prob in tab.action_iterator])
        # itertools.product(*[[1,2],[3,4],[5,6]]) ==> [(1, 3, 5), (1, 3, 6),...
        producted_actions = itertools.product(*all_tab_actions)
        merged_actions: List[Tuple[OptAction, Probability]] = []
        for pro_act in producted_actions:
            merged_actions.append(cls._create_merge_action(irgraph, pro_act))
        return merged_actions

    @classmethod
    def _merge_actions_pipelet_group(
        cls,
        irgraph: IrGraph,
        irgraph_pipe: IrGraphPipe,
        root: Union[Table, Condition],
        sink: Union[Table, Condition, Sink],
    ) -> List[Tuple[OptAction, Probability]]:
        """Merge actions from multiple tables by cross-product for a PipeletGroup."""
        merged_actions: List[Tuple[OptAction, Probability]] = []
        ActionProbTuple = Tuple[Union[Action, ConditionAction], Probability]
        name_to_normal_node = irgraph_pipe.name_to_normal_node
        # get all path from the root to the sink
        paths_between = nx.all_simple_paths(irgraph_pipe, source=root, target=sink)
        for path in paths_between:
            # remove the sink because it is not part of the pipelet group
            nodes_between = [node for node in path[:-1]]
            # if a path has only a condition node, we skip it because no action to run
            if nodes_between[-1].__class__.__name__ == "Condition":
                continue

            all_node_actions: List[List[ActionProbTuple]] = []
            for i in range(len(nodes_between)):
                node = nodes_between[i]
                assert node.__class__.__name__ in ["Table", "Condition"], f"Unexpected type {type(node)}."
                list_action: List[ActionProbTuple] = []
                for a, prob in node.action_iterator:
                    assert isinstance(a, Action) or isinstance(a, ConditionAction), f"Unexpected type {type(node)}."
                    if node.__class__.__name__ == "Table" and node.is_switch_table:
                        # For switch node, we need to check whether the action connects
                        # to its own next table's action
                        if i + 1 < len(nodes_between) and node.next_tables[a.name] != nodes_between[i + 1].name:
                            continue
                        # is switch node is the last table on the path, also need to make sure
                        # the action connects to its own next table's (sink's) action
                        if i + 1 == len(nodes_between) and node.next_tables[a.name] != sink.name:
                            continue

                    list_action.append((a, prob))
                all_node_actions.append(list_action)

            # itertools.product(*[[1,2],[3,4],[5,6]]) ==> [(1, 3, 5), (1, 3, 6),...
            producted_actions = itertools.product(*all_node_actions)
            for pro_act in producted_actions:
                # filter out impossible combinations based on if branch
                invalid_path = True
                for i in range(len(pro_act) - 1):
                    cur_act, _ = pro_act[i]
                    nxt_act, _ = pro_act[i + 1]
                    if isinstance(cur_act, ConditionAction):
                        next_node = cur_act.next_node
                        # if a ConditionAction connects to None (Sink), the path is invalid
                        # if a ConditionAction connects to a wrong action (wrong branch),
                        # the path is invalid
                        if (
                            next_node is None
                            or next_node.__class__.__name__ == "Sink"
                            or nxt_act.id not in name_to_normal_node[next_node].action_ids
                        ):
                            invalid_path = False
                            break
                if not invalid_path:
                    continue
                merged_actions.append(cls._create_merge_action(irgraph, pro_act))
        return merged_actions

    @classmethod
    def _get_group_cache_match_key(
        cls, ir_graph: IrGraph, nodes_to_cache: List[Union[Table, Condition]]
    ) -> Set[MatchKey]:
        cache_keys: Set[MatchKey] = set()

        data_access_infos = [
            OptUtils._extract_data_access_info(ir_graph, node)
            for node in nodes_to_cache
            if node.__class__.__name__ == "Table"
        ]
        # If there is only one table to cache, we do not need to do the dependency
        # analysis. Otherwise, the data read in the actions will also be viewed as
        # cache keys.
        if len(nodes_to_cache) == 1:
            assert nodes_to_cache[0].__class__.__name__ == "Table", (
                f"Single node pipelet group could only be composed of a Table, " f"but got {type(nodes_to_cache[0])}."
            )
            cache_keys = deepcopy(set(nodes_to_cache[0].keys))
        else:
            for info in data_access_infos:
                cache_keys = cache_keys.union(deepcopy(OptUtils._data_access_info_to_match_key(ir_graph, info)))
            # keys from conditions
            for node in nodes_to_cache:
                if node.__class__.__name__ == "Condition":
                    cache_keys = cache_keys.union(deepcopy(OptUtils._extract_condition_match_key(ir_graph, node)))
        # set key type to exact
        for key in cache_keys:
            key.match_type = MatchType.EXACT
        return cache_keys

    @classmethod
    def _irnode_create_group_cache_table(
        cls, ir_node: Union[Table, Condition], ir_graph: IrGraph, irgraph_pipe: "IrGraphPipe", cache_table_name
    ) -> CacheTable:
        """Create the cache table for a pipelet group."""
        group_cache_metadata = ir_node.optimized_metadata

        assert isinstance(group_cache_metadata, GroupCacheMetadata), (
            f"Table with optimized_type as GROUP_CACHED should have GroupCacheMetadata, "
            f"but we got {group_cache_metadata.__class__.__name__}"
        )
        nodes_to_cache = group_cache_metadata.cached_tables

        # Compute cache table keys
        cache_keys: Set[MatchKey] = OptUtils._get_group_cache_match_key(ir_graph, nodes_to_cache)

        # Prepare cache actions
        cache_action_probs = OptUtils._merge_actions_pipelet_group(
            ir_graph, irgraph_pipe, group_cache_metadata.root, group_cache_metadata.sink
        )
        for act, prob in cache_action_probs:
            ir_graph.add_action_from_obj(act)
        cache_action_ids = [a.id for a, prob in cache_action_probs]
        cache_action_names = [a.name for a, prob in cache_action_probs]

        # we set the max size to a pre-defined constant
        max_size = config.CACHE_TABLE_SIZE

        # Prepare cache default actions
        cache_no_action_json = {
            "name": "NoAction",
            "id": ir_graph.next_action_id(),
            "runtime_data": [],
            "primitives": [],
        }
        cache_default_action = ir_graph.add_action_from_json(cache_no_action_json, OptAction)
        cache_default_action_name = cache_default_action.name
        cache_default_action_id = cache_default_action.id
        cache_default_action_const = False
        cache_default_action_param = []
        cache_default_action_entry_const = False

        cache_action_ids.append(cache_default_action_id)

        # set a fixed value for other fields not captured by the IR
        cache_p4cjson_description = {
            "match_type": MatchType.EXACT,
            "type": "simple",
            "with_counters": False,
            "support_timeout": False,
            "direct_meters": None,
            "source_info": {"filename": "offload optimizer error: missing source"},
        }

        # Prepare next table selector
        last_table_next = group_cache_metadata.pipe_grp.sink.name
        # the sink is an object, but json uses None, so we do the transformation
        if last_table_next == "Sink":
            last_table_next = None
        # Set up the next table selector
        # If hit the cache, go to the next table of the last cached table
        # If miss the cache, fall back to the original pipeline
        # Note that we covert the __HIT__ and __MISS__ to action names because
        # the former has not been supported. In this case, the convertion is safe because
        # the default action will only be used when cache misses happen.
        selector_next_tables: Dict[ActionName, TableName] = {name: last_table_next for name in cache_action_names}
        selector_next_tables[cache_default_action_name] = group_cache_metadata.root.name
        cache_next_table_selector = NextTableSelector(next_tables=selector_next_tables, base_default_next=None)

        # Update the action probability for eval
        action_name_to_count: Dict[ActionName, int] = {}
        total_prob = 0
        for act, prob in cache_action_probs:
            action_name_to_count[act.name] = round(prob * 10000)
            total_prob += prob
        # if the whole group is an if-branch without else, the else action will
        # be ignored, because it does nothing, and hard to track its path.
        if not 1.01 > total_prob > 0.99:
            logger.warning(
                f"The total probability is not 1. Could be caused by the " f"empty else branch in the pipelet group."
            )
            # root = self.optimized_metadata.root
            # assert isinstance(root, Condition)
            # # if we include the root branch else, it should be still 1
            # assert 1.01>total_prob+root.false_probability>0.99, (
            #     f"The total probability should be 1."
            # )
        sum_count = sum(action_name_to_count.values())
        # sum_count/(sum_count+miss_count)=CACHE_HIT_RATE

        if config.ENABLE_CACHE_HIT_RATE_CHANGE:
            if config.CACHE_HIT_RATE_CHANGE_STEP:
                hit_rate = config.CACHE_HIT_RATE ** math.ceil(len(nodes_to_cache) / 5)
            else:
                hit_rate = config.CACHE_HIT_RATE ** len(nodes_to_cache)
        else:
            hit_rate = config.CACHE_HIT_RATE

        miss_count = round((1 - hit_rate) / hit_rate * sum_count)
        action_name_to_count[cache_default_action_name] = miss_count
        cache_next_table_selector.update_action_probability(action_name_to_count)

        # Update current table size and insertion rate
        # Cache has a fix size, so we directly use the max_size
        cache_current_size = max_size
        # a very simple heuristic to compute the insertion rate, need to enhance
        cache_insertion_rate = 1000 * len(cache_keys)
        cache_table = CacheTable(
            irgraph=ir_graph,
            id=ir_graph.next_table_id(),
            name=cache_table_name,
            keys=list(cache_keys),
            action_ids=cache_action_ids,
            default_action_id=cache_default_action_id,
            default_action_const=cache_default_action_const,
            default_action_param=cache_default_action_param,
            default_action_entry_const=cache_default_action_entry_const,
            max_size=max_size,
            # the optimized_metdata will be used by the entry population function to
            # add a ternary entry for the default action.
            optimized_metadata=GroupCacheMetadata(
                pipe_grp=group_cache_metadata.pipe_grp,
                root=group_cache_metadata.root,
                sink=group_cache_metadata.sink,
                cached_tables=group_cache_metadata.cached_tables,
            ),
            p4cjson_description=cache_p4cjson_description,
            next_table_selector=cache_next_table_selector,
            current_size=cache_current_size,
            entry_insertion_rate=cache_insertion_rate,
        )

        # compute merged entries
        cache_table.entry_builder = GroupCacheTableEntryBuilder(
            irgraph=ir_node.irgraph, source_table=ir_node, target_table=cache_table
        )
        return cache_table
