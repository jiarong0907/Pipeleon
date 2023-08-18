"""
Defines smart acc IR GeneralTable
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import Dict, List, Tuple, Union, Optional, Iterator, Any
from copy import deepcopy
from commons import types
from commons.base_logging import logger
from graph_optimizer.metadata import GroupOptimizedMetadata, OptimizedMetadata
from ir import misc
from commons.constants import EARLY_TERM_PRIM, DeviceTargetType, OptimizedType
from ir.action import ActionPrimitive, GeneralAction
from ir.ir_node import IrNode
from ir.match_key import MatchKey, MatchType
from ir.next_table_selector import NextTableSelector

from typing import TYPE_CHECKING
from ir.table_entry import TableEntry
from ir.table_entry_builder import (
    GeneralTableEntryBuilder,
)

if TYPE_CHECKING:
    from ir.irgraph import IrGraph

UNSUPPORTED_PRIMITIVES = ["install_exact_entry_1_0"]


class GeneralTable(IrNode, ABC):
    """
    Implements P4 table in IR
    """

    def __init__(
        self,
        irgraph: IrGraph,
        name: str,
        id: int,
        keys: List[MatchKey],
        action_ids: List[types.ActionId],
        default_action_id: types.ActionId,
        default_action_const: bool,
        default_action_param: List[types.ActionData],
        default_action_entry_const: bool,
        max_size: int,
        next_table_selector: NextTableSelector,
        # action_to_next_table:Dict[str,Tuple[str,ir_types.Probability]],
        entry_insertion_rate: Optional[int] = None,
        current_size: Optional[int] = None,  # the current table size (number of entries)
        target_type: DeviceTargetType = DeviceTargetType.UNASSIGNED,
        optimized_type: OptimizedType = OptimizedType.UNASSIGNED,
        optimized_metadata: Optional[Union[OptimizedMetadata, GroupOptimizedMetadata]] = None,
        assigned_size: Optional[int] = None,
        const_entries: Optional[List[Dict[str, Any]]] = None,
        p4cjson_description: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(name, id, target_type, optimized_type)
        self._irgraph = irgraph
        self._keys = keys
        self._action_ids = action_ids
        self._default_action_id = default_action_id
        self._default_action_const = default_action_const
        self._default_action_param = default_action_param
        self._default_action_entry_const = default_action_entry_const
        self._max_size = max_size
        self._entry_insertion_rate = entry_insertion_rate
        self._current_size = current_size
        self._optimized_metadata = optimized_metadata
        self._const_entries = const_entries
        self._entries: List[TableEntry] = []
        self._entry_builder: Optional[GeneralTableEntryBuilder] = None
        self._assigned_size = assigned_size
        self._p4cjson_description = p4cjson_description
        self._next_table_selector = next_table_selector
        self._next_table_selector.set_cur_table(self)
        # self._action_to_next_table = action_to_next_table

    @property
    def irgraph(self) -> IrGraph:
        return self._irgraph

    @property
    def optimized_metadata(self) -> Optional[Union[OptimizedMetadata, GroupOptimizedMetadata]]:
        """Return the optimization type of this table"""
        return self._optimized_metadata

    @optimized_metadata.setter
    def optimized_metadata(self, optimized_metadata: Union[OptimizedMetadata, GroupOptimizedMetadata]):
        self._optimized_metadata = optimized_metadata

    @property
    def max_size(self):
        """max table size"""
        return self._max_size

    @property
    def desc(self):
        """used for graph visualization"""
        desc_dict = OrderedDict()
        desc_dict["Name:"] = self.name
        desc_dict["Current table size:"] = self._current_size if self._current_size else -1
        desc_dict["Entry insertion rate:"] = self._entry_insertion_rate if self._entry_insertion_rate else -1
        desc_dict["Max size:"] = self._max_size
        desc_dict["Keys:"] = [str(k) for k in self._keys]
        desc_dict["Actions:"] = [self._irgraph.action_id_to_name[id] for id in self._action_ids]
        return misc.dict_to_desc(desc_dict)

    @property
    def keys(self) -> List[MatchKey]:
        return self._keys

    @property
    def current_size(self) -> Optional[int]:
        return self._current_size

    @current_size.setter
    def current_size(self, new_size: int):
        self._current_size = new_size

    @property
    def entry_insertion_rate(self) -> Optional[int]:
        return self._entry_insertion_rate

    @entry_insertion_rate.setter
    def entry_insertion_rate(self, new_rate: int):
        self._entry_insertion_rate = new_rate

    @property
    def next_tables(self) -> Dict[types.ActionName, types.IrNodeName]:
        return self._next_table_selector.next_tables

    @property
    def is_switch_table(self) -> bool:
        """Check if switch-case applied on this table"""
        return len(set(self._next_table_selector.next_tables.values())) > 1

    @property
    def action_to_probability(self) -> Dict[types.ActionName, types.Probability]:
        return self._next_table_selector.action_to_probability

    # @property
    # def action_to_next_table(self)->Dict[str,Tuple[str,ir_types.Probability]]:
    #     return self._action_to_next_table

    @property
    def action_iterator(self) -> Iterator[Tuple[GeneralAction, types.Probability]]:
        """ " iterates through all table actions (including default), and yeilds: [action, probability]"""
        assert self.default_action_name in self.action_names, (
            f"Table {self.name}'s default action ({self._default_action_id}) "
            f"should be in the action list, but we have {self._action_ids}"
        )
        action_id_to_action = self._irgraph.action_id_to_action
        for id in self._action_ids:
            action = action_id_to_action[id]
            action_probability = self._next_table_selector.action_probability(action.name)
            yield (action, action_probability)

    @property
    def default_action_name(self) -> str:
        return self._irgraph.action_id_to_name[self._default_action_id]

    @property
    def default_action_id(self) -> types.ActionId:
        return self._default_action_id

    @property
    def default_action_param(self) -> List[types.ActionData]:
        return self._default_action_param

    @property
    def action_names(self) -> List[str]:
        return [self._irgraph.action_id_to_name[id] for id in self._action_ids]

    @property
    def action_ids(self) -> List[types.ActionId]:
        return self._action_ids

    @property
    def action_id_to_name(self) -> Dict[types.ActionId, str]:
        return {id: self._irgraph.action_id_to_name[id] for id in self._action_ids}

    @property
    def early_term_action_names(self) -> List[str]:
        # for _, action_name, primitives, _ in self.action_iterator:
        #     print(f"Primitives of action {action_name} are {primitives}")
        return [
            action.name
            for (action, _) in self.action_iterator
            if len(EARLY_TERM_PRIM & {primitive.op for primitive in action.primitives}) > 0
        ]

    @property
    def unsupported_action_ids(self) -> List[int]:
        return [
            action.id
            for (action, _) in self.action_iterator
            if GeneralTable.has_unsupported_primitives(action.primitives)
        ]

    @property
    def entries(self) -> List[TableEntry]:
        return self._entries

    @entries.setter
    def entries(self, entries: List[TableEntry]):
        self._entries = deepcopy(entries)

    @property
    def entry_builder(self) -> GeneralTableEntryBuilder:
        return self._entry_builder

    @entries.setter
    def entry_builder(self, entry_builder: GeneralTableEntryBuilder):
        self._entry_builder = entry_builder

    def build_entries(self) -> List[TableEntry]:
        assert self._entry_builder is not None, (
            f"GeneralTable._entry_builder is None when build_entries is called. " f"GeneralTable name: {self.name}"
        )
        self._entries = self._entry_builder.build_entries()
        return self._entries

    @staticmethod
    def has_unsupported_primitives(primitives: List[ActionPrimitive]) -> bool:
        for primitive in primitives:
            if primitive.op in UNSUPPORTED_PRIMITIVES:
                return True
        return False

    def replace_action(
        self,
        old_action_id: types.ActionId,
        new_action: GeneralAction,
        new_next_table: str,
        default_action_param: List[types.ActionData],
    ) -> str:
        old_action_name = self.action_id_to_name[old_action_id]
        # Update _actions
        for i in range(len(self._action_ids)):
            if self._action_ids[i] == old_action_id:
                # TODO: remove action id from irgraph?
                self._action_ids[i] = new_action.id

        # Update _default_action
        if self._default_action_id == old_action_id:
            self._default_action_id = new_action.id
            self._default_action_param = default_action_param
        # Update _next_table_selector
        orig_next_table = self._next_table_selector.replace_action(
            old_action_name,
            new_action.name,
            new_next_table,
        )
        # # Update _action_to_next_table
        # orig_next_table, prob = self._action_to_next_table.pop(old_action_name)
        # self._action_to_next_table[new_action[2]] = (new_next_table, prob)
        return orig_next_table

    def remove_other_actions(self, to_keep: List[types.ActionId], new_default_action_id: types.ActionId):
        """Remove actions no in the provided list"""
        # Update _actions
        self._action_ids = [id for id in self.action_ids if id in to_keep]

        # Update _default_action
        if self._default_action_id not in to_keep:
            assert new_default_action_id in to_keep
            assert new_default_action_id != None, (
                f"Default action is removed, but the specified new default action name "
                f"{new_default_action_id} is not in the action_id list"
            )
            self._default_action_id = new_default_action_id

        # Update _next_table_selector
        to_keep_name = [self.irgraph.action_id_to_name[id] for id in to_keep]
        self._next_table_selector.remove_other_actions(to_keep_name)

    def replace_next_table(
        self,
        orig_next: Optional[types.IrNodeName],
        new_next: Optional[types.IrNodeName],
    ) -> None:
        self._next_table_selector.replace_next_table(orig_next, new_next)

    def update_prob_with_counts(self, action_name_to_count: Dict[types.ActionName, int]):
        """Update the prob part of next_table_selector with the counter
        values"""
        self._next_table_selector.update_action_probability(action_name_to_count)

    @property
    def match_type(self) -> MatchType:
        return self._get_match_type(self.keys)

    def _get_match_type(self, match_keys: List[MatchKey]) -> MatchType:
        """Determine the table match type by looking at its match keys.
        The priority is ternary > lpm > exact.
        """
        match_types = [mk.match_type for mk in match_keys]
        if MatchType.TERNARY in match_types:
            return MatchType.TERNARY
        elif MatchType.LPM in match_types:
            return MatchType.LPM
        else:
            # Both exact key and empty key has exact type
            return MatchType.EXACT

    def get_sons(self, check_prob: bool = True) -> Dict[types.Name, types.Probability]:
        sons = self._next_table_selector.next_table_to_probability
        # sons = {}
        # for (_,action_name,_base_actions,_) in self.action_iterator:
        #     if action_name=='base_action':
        #         next_table_key = _base_actions[0]
        #     else:
        #         next_table_key = action_name
        #     next_name,probability = self._action_to_next_table[next_table_key]
        #     sons[next_name]=sons.get(next_name,0) + probability
        #
        #
        # if 'default' in self._action_to_next_table:
        #     default_next = self._action_to_next_table['default']
        #     if default_next[0] not in sons:
        #         '''
        #         [Omer] added for andromeda, in case of next_tables:{'__MISS__':..}
        #         '''
        #         sons[default_next[0]] = default_next[1]
        #         print(f'Warning - changing son probability for {self.name}')
        #         cum_prob = sum(sons.values())
        #         for k,v in sons.items():
        #             sons[k] = v/cum_prob

        return sons

    @abstractmethod
    def update_mapping(self, cxt_id: int, mapping: Dict[str, Any]) -> None:
        raise NotImplementedError(f"The class of {self.name} needs to implement update_mapping")

    @classmethod
    def _p4cjson2ir(cls, table_dict: Dict, ir_graph) -> GeneralTable:
        """
        import table from p4c ir json format
        """
        # We use pop to remove the information from table_dict to avoid
        # duplicates of the same info and therefore avoid inconsistent updates
        # in the future
        table_id = table_dict.pop("id")
        table_name: str = table_dict.pop("name")
        action_ids = table_dict.pop("action_ids")
        default_entry = table_dict.pop("default_entry")
        default_action_id = default_entry["action_id"]

        default_action_const = default_entry["action_const"]
        default_action_param = default_entry["action_data"]
        default_action_entry_const = default_entry["action_entry_const"]
        if not table_name.startswith("$flex_cond_table"):
            # TODO: Assume action_const and action_entry_const are always False. Need to check
            assert (
                not default_entry["action_const"] and not default_entry["action_entry_const"]
            ), "'action_const' and 'action_entry_const' for default entry are not supported yet"

        next_table_selector = NextTableSelector(
            table_dict["next_tables"],
            table_dict["base_default_next"],
        )

        # action_to_next_table = {}
        # if ("__MISS__" in table_dict["next_tables"]):
        #     # This removes the usage of MISS, HIT in the resulting IR
        #     action_to_next_table["default"] = table_dict["next_tables"]["__MISS__"]
        #     if ("__HIT__" in table_dict["next_tables"]):
        #         for action_name in table_dict["actions"]:
        #             action_to_next_table[action_name] = table_dict["next_tables"]["__HIT__"]
        #     #print(table_name,action_to_next_table)
        # else:
        #     action_to_next_table = table_dict["next_tables"]
        #     action_to_next_table["default"] = table_dict["base_default_next"]
        # # TODO, probability
        # action_to_next_table_with_probability={}
        # even_prob  = 1./len(action_to_next_table)
        # for k,v in action_to_next_table.items():
        #     action_to_next_table_with_probability[k]=(v,even_prob)
        assert isinstance(table_name, str), table_name
        ir_table = cls(
            irgraph=ir_graph,
            id=table_id,
            name=table_name,
            keys=MatchKey._p4cjson2ir(table_dict.pop("key")),
            action_ids=action_ids,
            default_action_id=default_action_id,
            default_action_const=default_action_const,
            default_action_param=default_action_param,
            default_action_entry_const=default_action_entry_const,
            max_size=table_dict.pop("max_size"),
            p4cjson_description=deepcopy(table_dict),
            next_table_selector=next_table_selector,
            # action_to_next_table=action_to_next_table_with_probability
        )
        # ir_graph.update_table_id(table_dict["id"])
        return ir_table

    def _p4cir2json(self) -> Dict[str, Any]:
        """
        export table in p4c json ir format
        """
        action_ids = self._action_ids
        action_names = self.action_names
        # TODO put all of this as part of the object, and not pass it implicitly
        match_type = self._p4cjson_description["match_type"]
        table_type = self._p4cjson_description["type"]
        with_counters = self._p4cjson_description["with_counters"]
        support_timeout = self._p4cjson_description["support_timeout"]
        direct_meters = self._p4cjson_description["direct_meters"]
        key_list = [k._p4cir2json() for k in self.keys]
        base_default_next = self._next_table_selector.base_default_next
        # base_default_next = self._action_to_next_table["default"][0]
        next_tables = self._next_table_selector.next_tables
        # next_tables = {}
        # for a,(t,_) in self._action_to_next_table.items():
        #     if a == 'default':
        #         continue
        #     next_tables[a] = t
        # if len(next_tables)==0 and len(action_names)==1:
        #     # happens when the table points to sink
        #     # print(f"GeneralTable: {self.name}")
        #     # print(self._action_to_next_table)
        #     # print(f"action_names: {action_names}")
        #     next_tables[action_names[0]]=base_default_next
        assert len(next_tables) == len(action_names), "Export Error - missing next table in table ir representation"
        missing_source = {"filename": "offload optimizer error: missing source"}
        default_entry = {
            "action_id": self._default_action_id,
            "action_const": self._default_action_const,
            "action_data": self._default_action_param,
            "action_entry_const": self._default_action_entry_const,
        }
        table_dict = {
            "name": self.name,
            "id": self.id,
            "source_info": self._p4cjson_description.get("source_info", missing_source),
            "key": key_list,
            "match_type": match_type,  # TODO
            "type": table_type,  # TODO
            "max_size": self.max_size,
            "with_counters": with_counters,  # TODO
            "support_timeout": support_timeout,  # TODO
            "direct_meters": direct_meters,  # TODO
            "action_ids": action_ids,
            "actions": action_names,
            "base_default_next": base_default_next,
            "next_tables": next_tables,
            "default_entry": default_entry,
        }
        if self._const_entries is not None:
            table_dict["entries"] = self._const_entries
        return table_dict
