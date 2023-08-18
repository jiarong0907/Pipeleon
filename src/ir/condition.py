from __future__ import annotations
from typing import Dict, List, Tuple, Set, Union, Optional, Iterator, Any
from collections import OrderedDict
from commons import types
from commons.constants import DeviceTargetType, OptimizedType
import commons.config as config
from graph_optimizer.metadata import GroupCacheMetadata
from graph_optimizer.opt_utils import OptUtils
from ir import misc
from ir.action import ConditionAction, OptAction
from ir.action_parameter import ExpressionParam
from ir.ir_node import IrNode
from commons.base_logging import logger

from ir.match_key import MatchKey, MatchType
from ir.next_table_selector import NextTableSelector
from ir.table_entry_builder import GroupCacheTableEntryBuilder
from ir.opt_table import CacheTable

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ir.irgraph import IrGraph
    from ir.irgraph_pipe import IrGraphPipe
    from ir.opt_table import OptTable
    from ir.table import Table
    from graph_optimizer.metadata import GroupOptimizedMetadata


class Condition(IrNode):
    """
    Implements Conditional statement in IR
    """

    def __init__(
        self,
        irgraph: IrGraph,
        name: str,
        id: int,
        true_next: str,
        false_next: str,
        expression: ExpressionParam,
        source_info: Dict[str, Any],
        true_probability: types.Probability = 0.5,
        target_type: DeviceTargetType = DeviceTargetType.UNASSIGNED,
        optimized_type: OptimizedType = OptimizedType.UNASSIGNED,
        p4cjson_description: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(name, id, target_type, optimized_type)
        self._irgraph = irgraph
        self._true_next = true_next
        self._false_next = false_next
        self._true_probability = true_probability
        self._expression = expression
        self._source_info = source_info
        self._p4cjson_description = p4cjson_description
        assert true_probability <= 1, f"{self._name} has true probability larger than 1 ({true_probability})"

        # create actions
        self._true_action = ConditionAction(
            name=f"{self.name}_true", id=self.irgraph.next_action_id(), next_node=true_next
        )

        self._false_action = ConditionAction(
            name=f"{self.name}_false", id=self.irgraph.next_action_id(), next_node=false_next
        )
        # for group cache
        self._opt_table: Optional[OptTable] = None

    @property
    def irgraph(self) -> IrGraph:
        return self._irgraph

    @property
    def true_next(self) -> Optional[types.IrNodeName]:
        return self._true_next

    @true_next.setter
    def true_next(self, next_name: Optional[types.IrNodeName]):
        self._true_next = next_name

    @property
    def false_next(self) -> Optional[types.IrNodeName]:
        return self._false_next

    @false_next.setter
    def false_next(self, next_name: Optional[types.IrNodeName]):
        self._false_next = next_name

    @property
    def expression(self) -> ExpressionParam:
        return self._expression

    @property
    def source_info(self) -> Dict[str, Any]:
        return self._source_info

    @property
    def desc(self):
        """used for graph visualization"""
        desc_dict = OrderedDict()
        desc_dict["Condition name:"] = self.name
        desc_dict["Condition id:"] = self.id
        desc_dict["Source info:"] = self.source_info
        return misc.dict_to_desc(desc_dict)

    @property
    def true_probability(self) -> types.Probability:
        return self._true_probability

    @true_probability.setter
    def true_probability(self, new_prob: types.Probability):
        self._true_probability = new_prob

    @property
    def false_probability(self) -> types.Probability:
        return 1 - self._true_probability

    def get_sons(self) -> Dict[Optional[types.Name], types.Probability]:
        return {self._true_next: self.true_probability, self._false_next: self.false_probability}

    @property
    def next_tables(self) -> Dict[types.ActionName, Optional[types.IrNodeName]]:
        return {"true_next": self.true_next, "false_next": self.false_next}

    def replace_next_table(
        self,
        orig_next: Optional[types.IrNodeName],
        new_next: Optional[types.IrNodeName],
    ) -> None:
        if self.true_next == orig_next:
            self.true_next = new_next
        elif self.false_next == orig_next:
            self.false_next = new_next
        else:
            raise Exception(f"Didn't find matched next table name {orig_next} in branch {self.name}")

    @property
    def action_to_probability(self) -> Dict[types.ActionName, types.Probability]:
        return {"true_next": self.true_probability, "false_next": self.false_probability}

    @property
    def action_iterator(self) -> Iterator[Tuple[ConditionAction, types.Probability]]:
        """yeilds: [action, probability] for true and false branches"""
        yield (self._true_action, self.true_probability)
        yield (self._false_action, self.false_probability)

    @property
    def action_ids(self) -> List[types.ActionId]:
        return [self._true_action.id, self._false_action.id]

    def update_prob_with_counts(self, branch_name_to_count: Dict[types.BranchName, int]):
        total_count = sum(branch_name_to_count.values())
        # logger.info(f"total_count: {total_count}, {config.COUNTER_UPDATE_THRESHOLD}")
        # logger.info(
        #     f"setup: CACHE_HIT_RATE={config.CACHE_HIT_RATE}, "
        #     f"GROUP_CACHE_ENABLED={config.GROUP_CACHE_ENABLED}, "
        #     f"COUNTER_UPDATE_THRESHOLD={config.COUNTER_UPDATE_THRESHOLD}"
        # )
        if total_count < config.COUNTER_UPDATE_THRESHOLD:  # Don't update the prob if we have too few samples
            logger.info("cannot update")
            return
        self.true_probability = branch_name_to_count["true"] / total_count

    @property
    def opt_table(self) -> Optional[OptTable]:
        """Return the related Optimizer-created table for this original table"""
        assert config.GROUP_CACHE_ENABLED, f"This should only be invoked for group cache"
        return self._opt_table

    @opt_table.setter
    def opt_table(self, opt_table: OptTable):
        assert config.GROUP_CACHE_ENABLED, f"This should only be invoked for group cache"
        self._opt_table = opt_table

    @property
    def optimized_metadata(self) -> Optional[GroupOptimizedMetadata]:
        """Return the optimization type of this table"""
        assert config.GROUP_CACHE_ENABLED, f"This should only be invoked for group cache"
        return self._optimized_metadata

    @optimized_metadata.setter
    def optimized_metadata(self, optimized_metadata: GroupOptimizedMetadata):
        assert config.GROUP_CACHE_ENABLED, f"This should only be invoked for group cache"
        self._optimized_metadata = optimized_metadata

    def prepare_optimizer_created_tables(
        self,
        ir_graph: IrGraph,
        irgraph_pipe: IrGraphPipe,
        name_to_new_node: Dict[str, OptTable],
        name_to_removing_node: Dict[str, Table],
    ) -> None:
        assert config.GROUP_CACHE_ENABLED, f"This should only be invoked for group cache"

        if self.optimized_type == OptimizedType.UNASSIGNED:
            raise Exception("This table has not been optimized")

        # TODO: The following if-else can be done with polymorphism of class programming
        if self.optimized_type == OptimizedType.GROUP_CACHED:
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
            return
        else:
            raise TypeError(f"Unsupported optimization type {self.optimized_type}")

    def _create_group_cache_table(self, ir_graph: IrGraph, irgraph_pipe: IrGraphPipe, cache_table_name) -> CacheTable:
        assert config.GROUP_CACHE_ENABLED, f"This should only be invoked for group cache"
        return OptUtils._irnode_create_group_cache_table(self, ir_graph, irgraph_pipe, cache_table_name)

    @classmethod
    def _p4cjson2ir(cls, condition_dict: Dict, ir_graph: IrGraph):
        """Creates p4cir json from expression object"""
        name = condition_dict.pop("name")
        id = condition_dict.pop("id")
        true_next = condition_dict.pop("true_next")
        false_next = condition_dict.pop("false_next")
        expression = condition_dict.pop("expression")
        source_info = condition_dict.pop("source_info")

        assert isinstance(name, str), name
        ir_condition = cls(
            irgraph=ir_graph,
            name=name,
            id=id,
            true_next=true_next,
            false_next=false_next,
            expression=ExpressionParam._p4cjson2ir(expression),
            source_info=source_info,
            true_probability=0.5,  # TODO-probability
            p4cjson_description=condition_dict,
        )
        return ir_condition

    def _p4cir2json(self) -> Dict[str, Any]:
        """
        export condition in p4c json ir format
        """
        condition_dict = {
            "name": self.name,
            "id": self.id,
            "source_info": self.source_info,
            "expression": self._expression._p4cir2json(),
            "true_next": self._true_next,
            "false_next": self._false_next,
        }
        return condition_dict
