from copy import deepcopy
import math
from typing import Dict, List, Optional

from commons.types import ActionName, IrNodeName, Probability, TableName
import commons.config as config


class NextTableSelector:
    def __init__(
        self,
        next_tables: Dict[ActionName, TableName],
        base_default_next: Optional[TableName],
    ):
        """Two + one data structures maintined here

        Two common data structures for both hit-miss next_table and per-action
        next_table
            next_tables: Mapping from action_name to next_table name
            base_default_next: Just base_default_next

        One data structure for probability
            For hit-miss next_table, we have _hit_prob and _miss_prob
            For per-action next_table, we have _action_to_prob
            Both are init'ed with even prob

        Note that this helper class only handles operation related to next_tables.
        Action id related operations are handled by table.
        """
        self._cur_table = None
        self._next_tables = deepcopy(next_tables)
        self._base_default_next = base_default_next
        if "__HIT__" in next_tables:
            assert "__MISS__" in next_tables, (
                f"We assume next_tables either has both '__HIT__' and "
                f"'__MISS__' or none of them, but we got {next_tables}"
            )
            self._has_hit_miss = True
            self._hit_probability = 0.5
            self._miss_probability = 0.5
        else:
            assert "__MISS__" not in next_tables, (
                f"We assume next_tables either has both '__HIT__' and "
                f"'__MISS__' or none of them, but we got {next_tables}"
            )
            self._has_hit_miss = False
            self._action_to_probability: Dict[ActionName, Probability] = {}
            even_prob = 1.0 / len(self._next_tables)
            for action_name in self._next_tables.keys():
                self._action_to_probability[action_name] = even_prob

    @property
    def base_default_next(self) -> Optional[TableName]:
        return self._base_default_next

    @property
    def next_tables(self) -> Dict[ActionName, TableName]:
        return self._next_tables

    @property
    def action_to_probability(self) -> Dict[ActionName, Probability]:
        assert not self._has_hit_miss, f"hit-miss next_table does not support action_to_probability"
        return self._action_to_probability

    @property
    def next_table_to_probability(self) -> Dict[TableName, Probability]:
        assert self._cur_table is not None, (
            f"this next table selector has not be initialized with cur_table. " f"{self.next_tables}"
        )
        if self._has_hit_miss:
            assert len(self._cur_table.early_term_action_names) == 0, (
                f"For hit-miss table, we don't yet support getting next table "
                f"probability if some actions of this table can early terminate, but this table "
                f"has such early-terminated actions {self._cur_table.early_term_action_names}"
            )
            ret = {
                self._next_tables["__HIT__"]: self._hit_probability,
                self._next_tables["__MISS__"]: self._miss_probability,
            }
            total_probability = self._hit_probability + self._miss_probability
        else:
            ret = {}
            # print(f"table {self._cur_table.name} has early-terminated actions {self._cur_table.early_term_action_names}")
            total_probability = 0
            for action_name, next_table in self._next_tables.items():
                probability = self._action_to_probability[action_name]
                total_probability += probability
                if action_name not in self._cur_table.early_term_action_names:
                    ret[next_table] = ret.get(next_table, 0) + probability

        assert math.isclose(
            total_probability, 1
        ), f"Error - {self._cur_table} son cumulative prob: {total_probability}, {ret}"
        return ret

    def action_probability(self, action_name: str) -> float:
        return self._action_to_probability[action_name]

    def replace_action(
        self,
        old_action_name: ActionName,
        new_action_name: ActionName,
        new_next_table: TableName,
    ) -> TableName:
        """Return:
            original next table's name
        Note: Action id related updates are handle by upper layers, e.g., Table
        """
        assert not self._has_hit_miss, f"hit-miss next_table does not support replace_action"
        probability = self._action_to_probability.pop(old_action_name)
        orig_next_table = self._next_tables.pop(old_action_name)
        assert new_action_name not in self._next_tables, (
            f"The replacing action {new_action_name} already exists in the " f"next_tables {self._next_tables}"
        )
        self._next_tables[new_action_name] = new_next_table
        self._action_to_probability[new_action_name] = probability
        return orig_next_table

    def remove_other_actions(self, to_keep: List[str]) -> None:
        """Remove actions that are not in the to_keep list
        Note: Action id related updates are handle by upper layers, e.g., Table
        """
        assert not self._has_hit_miss, f"hit-miss next_table does not support remove_other_actions"
        # make sure every action name in to_keep is in the table
        for action_name in to_keep:
            assert action_name in self._next_tables, (
                f"action_name {action_name} was not in this table. The action list is "
                f"{list(self._next_tables.keys())}"
            )

        for action in list(self._next_tables.keys()):
            if action not in to_keep:
                self._next_tables.pop(action)
                self._action_to_probability.pop(action)
        new_total_probability = sum(self._action_to_probability.values())

        assert to_keep == list(self._next_tables.keys()), (
            f"actions to keep do not match the actions in next tables. to_keep: "
            f"{to_keep}, next_tables: {self._next_tables.keys()}"
        )

        for action in to_keep:
            self._action_to_probability[action] /= new_total_probability

    def replace_next_table(
        self,
        orig_next: Optional[IrNodeName],
        new_next: Optional[IrNodeName],
    ) -> None:
        """Replace all actions whose next table are orig_next to new_next
        Note: Action id related updates are handle by upper layers, e.g., Table
        """
        # make sure the provided orig_next is one of the next table
        assert orig_next in self._next_tables.values() or self._base_default_next == orig_next, (
            f"orig_next {orig_next} was not used by this table. The next table list is "
            f"{list(self._next_tables.values())}"
        )

        for action_name, next_table in self._next_tables.items():
            if next_table == orig_next:
                self._next_tables[action_name] = new_next
        if self._base_default_next == orig_next:
            self._base_default_next = new_next

    def update_action_probability(self, action_name_to_count: Dict[ActionName, int]) -> None:
        """Update action probability
        Note: Action id related updates are handle by upper layers, e.g., Table
        """
        assert not self._has_hit_miss, f"hit-miss next_table does not support update_action_probability"
        assert len(action_name_to_count) == len(self._next_tables), (
            f"The table has {len(self._next_tables)}, but only {len(action_name_to_count)} "
            f"actions' counter values are provided. This will lead to wrong probability calculation."
        )
        total_count = sum(action_name_to_count.values())

        if total_count < config.COUNTER_UPDATE_THRESHOLD:  # Don't update the prob if we have too few samples
            return
        for action_name, count in action_name_to_count.items():
            assert action_name in self._action_to_probability, (
                f"The action name {action_name} is not in the table. "
                f"The action names are {self._next_tables.keys()}"
            )
            self._action_to_probability[action_name] = count / total_count

    def set_cur_table(self, cur_table: "Table") -> None:
        self._cur_table = cur_table
