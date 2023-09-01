from __future__ import annotations
from copy import deepcopy
import itertools
import math
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple, Union
import operator
import commons.config as config
from commons.constants import (
    DeviceTargetType,
    OptimizedType,
    BITWIDTH_FOR_MAX_BITWIDTH,
)
from graph_optimizer.opt_utils import OptUtils
from graph_optimizer.metadata import CacheMetadata, GroupCacheMetadata, MergeMetadata, OptimizedMetadata
from ir.action import Action, ActionPrimitive, ActionRuntimeDataItem, OptAction
from ir.condition import Condition
from ir.action_parameter import FieldParam, HeaderParam
from ir.match_key import MatchKey, MatchType
from ir.next_table_selector import NextTableSelector
from ir.opt_table import CacheTable, ExtensionTable, MergeTable, OptTable, SoftcopyTable
from ir.general_table import GeneralTable
from commons import types
from commons.base_logging import logger
from ir.table_entry_builder import (
    CacheTableEntryBuilder,
    ExtensionTableEntryBuilder,
    GroupCacheTableEntryBuilder,
    MergeTableEntryBuilder,
    SoftcopyTableEntryBuilder,
    TableEntryBuilder,
)

if TYPE_CHECKING:
    from ir.irgraph import IrGraph
    from graph_optimizer.pipelet import PipeletGroup
    from ir.ir_node import Root, Sink
    from ir.irgraph_pipe import IrGraphPipe


class Table(GeneralTable):
    """The user table that is the original table in the json, and may or may not
    have been optimized by planner"""

    def __init__(
        self,
        irgraph: IrGraph,
        name: str,
        id: int,
        keys: List[MatchKey],
        action_ids: List[types.ActionId],
        default_action_id: types.ActionId,
        default_action_const: bool,
        default_action_param: List[str],
        default_action_entry_const: bool,
        max_size: int,
        next_table_selector: NextTableSelector,
        # action_to_next_table:Dict[str,Tuple[str,ir_types.Probability]],
        entry_insertion_rate: Optional[int] = None,
        current_size: Optional[int] = None,  # the current table size (number of entries)
        target_type: DeviceTargetType = DeviceTargetType.UNASSIGNED,
        optimized_type: OptimizedType = OptimizedType.UNASSIGNED,
        optimized_metadata: Optional[OptimizedMetadata] = None,
        assigned_size: Optional[int] = None,
        const_entries: Optional[List[Dict[str, Any]]] = None,
        p4cjson_description: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            irgraph,
            name,
            id,
            keys,
            action_ids,
            default_action_id,
            default_action_const,
            default_action_param,
            default_action_entry_const,
            max_size,
            next_table_selector,
            # action_to_next_table,
            entry_insertion_rate,
            current_size,  # the current table size (number of entries)
            target_type,
            optimized_type,
            optimized_metadata,
            assigned_size,
            const_entries,
            p4cjson_description,
        )
        self.entry_builder = TableEntryBuilder(irgraph, self, self)
        self._opt_table: Optional[OptTable] = None

    @property
    def opt_table(self) -> Optional[OptTable]:
        """Return the related Optimizer-created table for this original table"""
        assert not isinstance(self, OptTable), (
            f"Only a normal (non-optimizer-generated) table can have an "
            f"OptTable, so this table {self} (of class {self.__class__.__name__}) "
            f"should never use opt_table property"
        )
        return self._opt_table

    @opt_table.setter
    def opt_table(self, opt_table: OptTable):
        assert not isinstance(self, OptTable), (
            f"Only a normal (non-optimizer-generated) table can have an "
            f"OptTable, so this table {self} (of class {self.__class__.__name__}) "
            f"should never use opt_table property"
        )
        self._opt_table = opt_table

    def _create_extension_table(
        self,
        unsupported_action_ids: List[types.ActionId],
        ir_graph,
    ) -> ExtensionTable:
        # Create a table same as the original
        original_table_json = self._p4cir2json()
        original_table_json["name"] += "$ext"
        # clear match key and set table type to exact
        # we reverse this for the workaround. See this issue:
        # https://gitlab.com/MellanoxAD/offloadoptimizer/-/issues/10
        # original_table_json["key"] = []
        # original_table_json["match_type"] = "exact"
        extension_table = ExtensionTable._p4cjson2ir(
            original_table_json,
            ir_graph,
        )

        extension_table.optimized_metadata = self.optimized_metadata

        # Update current table size and insertion rate
        extension_table.current_size = 0
        extension_table.entry_insertion_rate = 0

        # Remove supported actions in extension_table and keep unsupported actions
        # as it is in original table because we will later remove them from the
        # original table
        new_default_action_id = self._default_action_id
        # we use the first unsupported action as the default action, but this
        # actually does not matter since the original table in ASIC should never
        # forward traffic of default action to the extension table in ARM
        if new_default_action_id not in unsupported_action_ids:
            new_default_action_id = unsupported_action_ids[0]
        extension_table.remove_other_actions(unsupported_action_ids, new_default_action_id)

        extension_table.entry_builder = ExtensionTableEntryBuilder(
            irgraph=self.irgraph, source_table=self, target_table=extension_table
        )

        return extension_table

    def _create_copy_table(self, ir_graph) -> SoftcopyTable:
        # Create a table same as the original
        p4cjson = {"actions": ir_graph.actions}
        original_table_json = self._p4cir2json()
        original_table_json["name"] += "$cpy"
        copy_table = SoftcopyTable._p4cjson2ir(
            original_table_json,
            ir_graph,
        )

        copy_table.optimized_metadata = self.optimized_metadata

        # Update current table size and insertion rate
        assert self.current_size != None, f"Current size of original table {self.name} was not set."
        assert self.entry_insertion_rate != None, f"Insertion rate of original table {self.name} was not set."
        copy_table.current_size = self.current_size
        copy_table.entry_insertion_rate = self.entry_insertion_rate
        copy_table.entry_builder = SoftcopyTableEntryBuilder(
            irgraph=self.irgraph, source_table=self, target_table=copy_table
        )

        # We don't avoid duplicate actions between copy table and the original
        # one, because later during splitting they will always be put in
        # different contexts, so duplicated action_ids are fine
        # TODO: Check whether this is true
        return copy_table

    def _create_cache_table(self, ir_graph: IrGraph, irgraph_pipe: IrGraphPipe, cache_table_name) -> CacheTable:
        assert isinstance(self.optimized_metadata, CacheMetadata), (
            f"Table with optimized_type as CACHED should have CacheMetadata, "
            f"but we got {self.optimized_metadata.__class__.__name__}"
        )
        tables_to_cache = self.optimized_metadata.cached_tables

        # Compute cache table keys
        data_access_infos = [OptUtils._extract_data_access_info(ir_graph, table) for table in tables_to_cache]

        cache_keys: Set[MatchKey] = set()
        # If there is only one table to cache, we do not need to do the dependency
        # analysis. Otherwise, the data read in the actions will also be viewed as
        # cache keys.
        if len(tables_to_cache) == 1:
            cache_keys = deepcopy(set(tables_to_cache[0].keys))
        else:
            for info in data_access_infos:
                cache_keys = cache_keys.union(deepcopy(OptUtils._data_access_info_to_match_key(ir_graph, info)))
        # set key type to exact
        for key in cache_keys:
            key.match_type = MatchType.EXACT

        # Prepare cache actions
        cache_action_probs = OptUtils._merge_actions_pipelet(ir_graph, tables_to_cache)
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
            "primitives": [Table._get_record_match_key_primitive_json(cache_table_name)],
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
            "match_type": MatchType.EXACT.value,
            "type": "simple",
            "with_counters": False,
            "support_timeout": False,
            "direct_meters": None,
            "source_info": {"filename": "offload optimizer error: missing source"},
        }

        # Prepare next table selector
        last_table_next = list(tables_to_cache[-1].next_tables.values())
        assert len(set(last_table_next)) == 1, (
            f"The last table of the cache should have only one next table. "
            f"This is also true for the last table in the pipelet, which should "
            f"have only one outgoing edge."
        )
        # Set up the next table selector
        # If hit the cache, go to the next table of the last cached table
        # If miss the cache, fall back to the original pipeline
        # Note that we covert the __HIT__ and __MISS__ to action names because
        # the former has not been supported. In this case, the convertion is safe because
        # the default action will only be used when cache misses happen.
        selector_next_tables: Dict[types.ActionName, types.TableName] = {
            name: last_table_next[0] for name in cache_action_names
        }
        selector_next_tables[cache_default_action_name] = tables_to_cache[0].name
        cache_next_table_selector = NextTableSelector(next_tables=selector_next_tables, base_default_next=None)

        # Update the action probability for eval
        action_name_to_count: Dict[types.ActionName, int] = {}
        total_prob = 0
        for act, prob in cache_action_probs:
            action_name_to_count[act.name] = round(prob * 10000)
            total_prob += prob
        assert math.isclose(total_prob, 1), f"The total probability should be 1."
        sum_count = sum(action_name_to_count.values())
        # sum_count/(sum_count+miss_count)=CACHE_HIT_RATE

        if config.ENABLE_CACHE_HIT_RATE_CHANGE:
            if config.CACHE_HIT_RATE_CHANGE_STEP:
                hit_rate = config.CACHE_HIT_RATE ** math.ceil(len(tables_to_cache) / 2)
            else:
                hit_rate = config.CACHE_HIT_RATE ** len(tables_to_cache)
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
            optimized_metadata=CacheMetadata(
                start_table_id=self.optimized_metadata.start_table_id,
                length=self.optimized_metadata.length,
                cached_tables=self.optimized_metadata.cached_tables,
            ),
            p4cjson_description=cache_p4cjson_description,
            next_table_selector=cache_next_table_selector,
            current_size=cache_current_size,
            entry_insertion_rate=cache_insertion_rate,
        )

        # compute merged entries
        cache_table.entry_builder = CacheTableEntryBuilder(
            irgraph=self.irgraph, source_table=self, target_table=cache_table
        )
        return cache_table

    def _create_merge_table(self, ir_graph: IrGraph, irgraph_pipe: IrGraphPipe, merge_table_name) -> MergeTable:
        """Create the merge table for the selected segment."""
        assert isinstance(self.optimized_metadata, MergeMetadata), (
            f"Table with optimized_type as MERGED should have MergeMetadata, "
            f"but we got {self.optimized_metadata.__class__.__name__}"
        )
        tables_to_merge = self.optimized_metadata.merged_tables
        assert len(tables_to_merge) == 2, f"We only support merging two tables for now"

        # For now, we just simply concatenate all match keys. This can be optimized
        # by removing duplicated keys, but it will make the entry merging more complicated.
        merged_keys: List[MatchKey] = list(itertools.chain(*[t.keys for t in tables_to_merge]))
        # If one of the table is ternary, the merged table will be ternary, and we need to
        # convert all keys to be ternary. This is needed for adding a default ternary entry
        # for the merged table.
        has_ternary_table = True if MatchType.TERNARY in [t.match_type for t in tables_to_merge] else False
        if has_ternary_table:
            for mkey in merged_keys:
                mkey.match_type = MatchType.TERNARY

        # Prepare merged actions
        merged_action_probs = OptUtils._merge_actions_pipelet(ir_graph, tables_to_merge)
        for act, prob in merged_action_probs:
            ir_graph.add_action_from_obj(act)
        if not has_ternary_table:
            for table in tables_to_merge:
                for action, _ in table.action_iterator:
                    assert isinstance(action, Action)
                    action.post_opt_action_counters.append((DeviceTargetType.HW_STEERING, action.id))
        merged_action_ids = [a.id for a, prob in merged_action_probs]
        merged_action_names = [a.name for a, prob in merged_action_probs]

        # we set the max size to the cross-product of all merged tables
        max_size = 1
        for tab in tables_to_merge:
            max_size *= tab.max_size

        # Prepare merged default actions
        merged_no_action_json = {
            "name": "NoAction",
            "id": ir_graph.next_action_id(),
            "runtime_data": [],
            "primitives": [],
        }
        merged_default_action = ir_graph.add_action_from_json(merged_no_action_json, OptAction)
        merged_default_action_name = merged_default_action.name
        merged_default_action_id = merged_default_action.id
        merged_default_action_const = False
        merged_default_action_param = []
        merged_default_action_entry_const = False

        merged_action_ids.append(merged_default_action_id)

        # set a fixed value for other fields not captured by the IR
        merged_p4cjson_description = {
            "match_type": self._get_match_type(merged_keys).value,
            "type": "simple",
            "with_counters": False,
            "support_timeout": False,
            "direct_meters": None,
            "source_info": {"filename": "offload optimizer error: missing source"},
        }

        # Prepare next table selector
        last_mrg_tab = tables_to_merge[-1]
        last_table_next = list(last_mrg_tab.next_tables.values())
        assert len(set(last_table_next)) == 1, (
            f"The last table of the cache should have only one next table. "
            f"This is also true for the last table in the pipelet, which should "
            f"have only one outgoing edge."
        )
        selector_next_tables: Dict[types.ActionName, types.TableName] = {
            name: last_table_next[0] for name in merged_action_names
        }
        if merged_p4cjson_description["match_type"] == "ternary":
            # Ternary merged table will completely replace the original table
            # Therefore, this should never be used because a default entry has been added
            # So its value can be anything
            selector_next_tables[merged_default_action_name] = last_table_next[0]
        else:
            # For exact and lpm, we need to fall back to the original pipeline if miss.
            # If hit the merged table, go to the next table of the last merged table
            # If miss the merged table, fall back to the original pipeline
            selector_next_tables[merged_default_action_name] = tables_to_merge[0].name
        # Note that we covert the __HIT__ and __MISS__ to action names because
        # the former has not been supported. In this case, the convertion is safe because
        # the default action will only be used when merged table is missed.
        merged_next_table_selector = NextTableSelector(next_tables=selector_next_tables, base_default_next=None)

        # Update the action probability for eval
        action_name_to_count: Dict[types.ActionName, int] = {}
        total_prob = 0
        for act, prob in merged_action_probs:
            action_name_to_count[act.name] = round(prob * 10000)
            total_prob += prob

        assert math.isclose(total_prob, 1), f"The total probability should be 1."

        if merged_p4cjson_description["match_type"] == "ternary":
            # completely replace the original pipeline, should never be hit
            action_name_to_count[merged_default_action_name] = 0
        else:
            sum_count = sum(action_name_to_count.values())
            # sum_count/(sum_count+miss_count)=MERGE_HIT_RATE
            miss_count = round((1 - config.MERGE_HIT_RATE) / config.MERGE_HIT_RATE * sum_count)
            action_name_to_count[merged_default_action_name] = miss_count
        merged_next_table_selector.update_action_probability(action_name_to_count)

        # Update current table size
        # We use simple cross-product because the table entries are computed
        # by cross-product.
        merged_current_size = 1
        for t in tables_to_merge:
            assert t.current_size != None, f"The current size of table {t.name} was not set."
            merged_current_size = merged_current_size * t.current_size

        # Update insertion rate
        merged_insertion_rate = 0
        for t in tables_to_merge:
            assert t.entry_insertion_rate != None, f"The insertion rate of table {t.name} was not set."
            # the insertion rate incurred by table t is its insertion rate times all other tables' sizes
            insertion_rate_t = t.entry_insertion_rate
            for k in tables_to_merge:
                if t.id != k.id:
                    insertion_rate_t = insertion_rate_t * k.current_size
            merged_insertion_rate += insertion_rate_t

        merged_table = MergeTable(
            irgraph=ir_graph,
            id=ir_graph.next_table_id(),
            name=merge_table_name,
            keys=merged_keys,
            action_ids=merged_action_ids,
            default_action_id=merged_default_action_id,
            default_action_const=merged_default_action_const,
            default_action_param=merged_default_action_param,
            default_action_entry_const=merged_default_action_entry_const,
            max_size=max_size,
            # the optimized_metdata will be used by the entry population function to
            # add a ternary entry for the default action.
            optimized_metadata=MergeMetadata(
                start_table_id=self.optimized_metadata.start_table_id,
                length=self.optimized_metadata.length,
                merged_tables=self.optimized_metadata.merged_tables,
            ),
            p4cjson_description=merged_p4cjson_description,
            next_table_selector=merged_next_table_selector,
            current_size=merged_current_size,
            entry_insertion_rate=merged_insertion_rate,
        )

        # compute merged entries
        merged_table.entry_builder = MergeTableEntryBuilder(
            irgraph=self.irgraph, source_table=self, target_table=merged_table
        )
        return merged_table

    def _create_group_cache_table(self, ir_graph: IrGraph, irgraph_pipe: IrGraphPipe, cache_table_name) -> CacheTable:
        return OptUtils._irnode_create_group_cache_table(self, ir_graph, irgraph_pipe, cache_table_name)

    def prepare_optimizer_created_tables(
        self,
        ir_graph: IrGraph,
        irgraph_pipe: IrGraphPipe,
        name_to_new_node: Dict[str, OptTable],
        name_to_removing_node: Dict[str, Table],
    ) -> None:
        if self.optimized_type == OptimizedType.UNASSIGNED:
            raise Exception("This table has not been optimized")

        # TODO: The following if-else can be done with polymorphism of class programming
        if self.optimized_type == OptimizedType.SEMI_SUPPORTED:
            unsupported_action_ids = self.unsupported_action_ids
            self.optimized_type = OptimizedType.HW_STEERING
            # Add extension table
            # Set extension table with arm subtarget
            extension_table = self._create_extension_table(
                unsupported_action_ids,
                ir_graph,
            )
            extension_table.optimized_type = OptimizedType.SW_STEERING
            self.opt_table = extension_table
            assert extension_table.name not in name_to_new_node, (
                f"Duplicate extension tables with table name: " f"{extension_table.name}"
            )
            name_to_new_node[extension_table.name] = extension_table

            for original_action, _ in self.action_iterator:
                assert isinstance(original_action, Action)
                if original_action.id in unsupported_action_ids:
                    # Create NoAction for replacement in original table
                    new_action = Table._create_replace_action(original_action.id, ir_graph)
                    new_action.optimized_from = [original_action]
                    original_action.post_opt_action_counters = [(DeviceTargetType.HW_STEERING, original_action.id)]

                    # Replace the unsupported action in original table with
                    # NoAction and set its next_table to the extension table
                    default_action_param = []  # For replace action (i.e., NoAction), param is empty
                    original_next = self.replace_action(
                        original_action.id,
                        new_action,
                        extension_table.name,
                        default_action_param,
                    )
                else:
                    original_action.post_opt_action_counters = [(DeviceTargetType.HW_STEERING, original_action.id)]

        elif self.optimized_type == OptimizedType.COPIED:
            self.optimized_type = OptimizedType.HW_STEERING

            # Add copy table
            # Set copy table with arm subtarget
            copy_table = self._create_copy_table(ir_graph)
            copy_table.optimized_type = OptimizedType.SW_STEERING
            self.opt_table = copy_table
            assert copy_table.name not in name_to_new_node, (
                f"Duplicate copy tables with table name: " f"{copy_table.name}"
            )
            name_to_new_node[copy_table.name] = copy_table

            for action, _ in self.action_iterator:
                assert isinstance(action, Action)
                action.post_opt_action_counters = [
                    (DeviceTargetType.HW_STEERING, action.id),
                    (DeviceTargetType.SW_STEERING, action.id),
                ]

        elif self.optimized_type == OptimizedType.CACHED:
            assert isinstance(self.optimized_metadata, CacheMetadata), (
                f"Table with optimized_type as CACHED should have CacheMetadata, "
                f"but we got {self.optimized_metadata.__class__.__name__}"
            )
            self.optimized_type = OptimizedType.HW_STEERING
            cache_table_name = self.optimized_metadata.cached_tables[0].name + "$cch"
            if cache_table_name not in name_to_new_node:
                cache_table = self._create_cache_table(ir_graph, irgraph_pipe, cache_table_name)
                cache_table.optimized_type = OptimizedType.HW_STEERING
                cache_table.change_cached_table_actions()
                name_to_new_node[cache_table_name] = cache_table
            self.opt_table = name_to_new_node[cache_table_name]

        elif self.optimized_type == OptimizedType.MERGED:
            assert isinstance(self.optimized_metadata, MergeMetadata), (
                f"Table with optimized_type as MERGED should have MergeMetadata, "
                f"but we got {self.optimized_metadata.__class__.__name__}"
            )
            self.optimized_type = OptimizedType.HW_STEERING
            merge_table_name = self.optimized_metadata.merged_tables[0].name + "$mrg"
            if merge_table_name not in name_to_new_node:
                merge_table = self._create_merge_table(ir_graph, irgraph_pipe, merge_table_name)
                merge_table.optimized_type = OptimizedType.HW_STEERING
                name_to_new_node[merge_table_name] = merge_table
            else:
                merge_table = name_to_new_node[merge_table_name]
            self.opt_table = merge_table
            if merge_table._p4cjson_description["match_type"] == "ternary":
                name_to_removing_node[self.name] = self
        elif self.optimized_type == OptimizedType.GROUP_CACHED:
            assert isinstance(self.optimized_metadata, GroupCacheMetadata), (
                f"Table with optimized_type as GROUP_CACHED should have GroupCacheMetadata, "
                f"but we got {self.optimized_metadata.__class__.__name__}"
            )
            self.optimized_type = OptimizedType.HW_STEERING
            cache_table_name = self.optimized_metadata.root.name + "$cch"
            if cache_table_name not in name_to_new_node:
                cache_table = self._create_group_cache_table(ir_graph, irgraph_pipe, cache_table_name)
                cache_table.optimized_type = OptimizedType.HW_STEERING
                name_to_new_node[cache_table_name] = cache_table
            self.opt_table = name_to_new_node[cache_table_name]
        elif self.optimized_type == OptimizedType.HW_STEERING:
            for action, _ in self.action_iterator:
                assert isinstance(action, Action)
                action.post_opt_action_counters = [
                    (DeviceTargetType.HW_STEERING, action.id),
                ]
        elif self.optimized_type == OptimizedType.SW_STEERING:
            for action, _ in self.action_iterator:
                assert isinstance(action, Action)
                action.post_opt_action_counters = [
                    (DeviceTargetType.SW_STEERING, action.id),
                ]
            return
        else:
            raise TypeError(f"Unsupported optimization type {self.optimized_type}")

    @staticmethod
    def _create_replace_action(original_action_id: int, ir_graph: IrGraph) -> OptAction:
        original_action_name = ir_graph.action_id_to_name[original_action_id]
        no_action_json = {
            "name": original_action_name + "$rep",
            "id": ir_graph.next_action_id(),
            "runtime_data": [],
            "primitives": [
                {
                    "op": "count",
                    "parameters": [
                        {"type": "counter_array", "value": "$flex_action_counter"},
                        {"type": "hexstr", "value": "{0:#0{1}x}".format(original_action_id, 8)},
                    ],
                    "source_info": {"filename": "Automated flex action counter"},
                }
            ],
        }
        return ir_graph.add_action_from_json(no_action_json, OptAction)

    @staticmethod
    def _get_record_match_key_primitive_json(cache_table_name: str) -> Dict[str, Any]:
        return {
            "op": "record_match_key",
            "parameters": [
                {
                    "type": "string",
                    "value": cache_table_name,
                }
            ],
        }

    @staticmethod
    def _get_record_path_primitive_json(action_id: int) -> Dict[str, Any]:
        return {"op": "record_action_id", "parameters": []}

    @staticmethod
    def _get_insert_cache_entry_primitive_json(cache_table: CacheTable) -> Dict[str, Any]:
        return {
            "op": "install_cache_entry",
            "parameters": [
                {
                    "type": "string",
                    "value": cache_table.name,
                },
                {"type": "header_stack", "value": "$action_data_stack"},
            ],
        }

    def add_record_path_to_all_actions(self) -> None:
        for action, _ in self.action_iterator:
            record_path_primitive_json = Table._get_record_path_primitive_json(action.id)
            action.prepend_primitive_from_json(record_path_primitive_json)
            for runtime_data_id in range(len(action.runtime_data)):
                # Add primitives that push this action data's runtime value to
                # action_data_stack
                push_primitive = {
                    "op": "push",
                    "parameters": [
                        {"type": "header_stack", "value": "$action_data_stack"},
                        {"type": "hexstr", "value": "0x1"},
                    ],
                }
                set_valid_primitive = {
                    "op": "add_header",
                    "parameters": [{"type": "header", "value": "$action_data_stack[0]"}],
                }
                value_assign_primitive = {
                    "op": "assign",
                    "parameters": [
                        {"type": "field", "value": ["$action_data_stack[0]", "value"]},
                        {
                            "type": "expression",
                            "value": {
                                "type": "expression",
                                "value": {
                                    "op": "&",
                                    "left": {
                                        "type": "local",
                                        "value": runtime_data_id,
                                    },
                                    "right": {"type": "hexstr", "value": "0xffffffffffffffff"},
                                },
                            },
                        },
                    ],
                }
                bit_width_assign_primitive = {
                    "op": "assign",
                    "parameters": [
                        {"type": "field", "value": ["$action_data_stack[0]", "bit_width"]},
                        {
                            "type": "hexstr",
                            "value": "{0:#0{1}x}".format(
                                action.runtime_data[runtime_data_id].bitwidth,
                                BITWIDTH_FOR_MAX_BITWIDTH // 4,
                            ),
                        },
                    ],
                }
                action.prepend_primitive_from_json(bit_width_assign_primitive)
                action.prepend_primitive_from_json(value_assign_primitive)
                action.prepend_primitive_from_json(set_valid_primitive)
                action.prepend_primitive_from_json(push_primitive)

    def add_insert_cache_entry_to_all_actions(self, cache_table: CacheTable) -> None:
        for action, _ in self.action_iterator:
            insert_cache_entry_primitive_json = Table._get_insert_cache_entry_primitive_json(cache_table)
            action.prepend_primitive_from_json(insert_cache_entry_primitive_json)

    def update_mapping(self, cxt_id: int, mapping: Dict[str, Any]) -> None:
        # Update table mapping
        table_mapping = mapping["tables"]

        if self.name not in table_mapping:
            table_mapping[self.name] = {}

        assert "entries" not in table_mapping[self.name], (
            f"Only one table should try to populate entries for the original "
            f"table, but this table {self.name} has been tried twice"
        )
        table_mapping[self.name] = {"entries": [entry._p4cir2json() for entry in self.entries]}

        assert "name" not in table_mapping[self.name], (
            f"Only one table should determine the name of the original "
            f"table, but this table {self.name} has been determined twice"
        )
        table_mapping[self.name]["name"] = self.name

        assert "cxt" not in table_mapping[self.name], (
            f"Only one table should determine the context id of the original "
            f"table, but this table {self.name} has been determined twice"
        )
        table_mapping[self.name]["cxt"] = cxt_id

        assert "default_action_name" not in table_mapping[self.name], (
            f"Only one table should determine the default action name of the original "
            f"table, but this table {self.name} has been determined twice"
        )
        table_mapping[self.name]["default_action_name"] = self.default_action_name

        assert "default_action_param" not in table_mapping[self.name], (
            f"Only one table should determine the default action param of the original "
            f"table, but this table {self.name} has been determined twice"
        )
        table_mapping[self.name]["default_action_param"] = deepcopy(self.default_action_param)
