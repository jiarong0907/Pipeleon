from dataclasses import dataclass, field
from typing import Any, Dict, List

from commons.types import ActionId, BranchName, Bytes, CondName, TableName


@dataclass
class ActionMeta:
    action_name: str
    action_id: int

    def set_table_info(self, table_name):
        self.table_name = table_name


@dataclass
class TableMeta:
    actions: List[ActionId]


@dataclass
class TableCountProfile:
    counts: Dict[ActionId, int] = field(default_factory=dict)
    action_meta: Dict[ActionId, ActionMeta] = field(default_factory=dict)
    drop_count: int = 0


@dataclass
class CondCountProfile:
    counts: Dict[BranchName, int] = field(default_factory=dict)


@dataclass
class RuntimeStates:
    table_to_counts: Dict[TableName, TableCountProfile]
    cond_to_counts: Dict[CondName, CondCountProfile]
    table_to_size: Dict[TableName, int]
    table_to_entry_insertion_count: Dict[TableName, int]
    total_memory: Bytes
    total_entry_insertion_bandwidth: int
    mapping_dict: Dict[str, Any]

    def get_counter_info(self) -> str:
        table_count_str = ""
        for table_name in self.table_to_counts.keys():
            profile = self.table_to_counts[table_name]
            table_count_str += (
                f">>>table_name: {table_name}, tab_counter: {profile.counts}, drops: {profile.drop_count}\n"
            )
            # for action_id in profile.counts.keys():
            #     action_name = profile.action_meta[action_id].action_name
            #     counter = profile.counts[action_id]
            #     table_count_str += f"action_name: {action_name}, counter: {counter}\n"
            # table_count_str += f"Drop counter: {profile.drop_count}\n\n"

        for cond_name in self.cond_to_counts.keys():
            table_count_str += f">>>cond_name: {cond_name}, cond_counter: {self.cond_to_counts[cond_name]}\n"

        return table_count_str

    # TODO: add mapping_dict string
    def __str__(self) -> str:
        table_count_str = ""
        for table_name in self.table_to_counts.keys():
            table_count_str += f">>>table_name: {table_name}\n"
            profile = self.table_to_counts[table_name]
            for action_id in profile.counts.keys():
                action_name = profile.action_meta[action_id].action_name
                counter = profile.counts[action_id]
                table_count_str += f"action_name: {action_name}, counter: {counter}\n"
            table_count_str += f"Drop counter: {profile.drop_count}\n\n"

        table_size_str = ""
        for table_name in self.table_to_size.keys():
            table_size_str += f"table_name: {table_name}, " f"size: {self.table_to_size[table_name]}\n"

        table_insert_str = ""
        for table_name in self.table_to_entry_insertion_count.keys():
            table_insert_str += (
                f"table_name: {table_name}, " f"size: {self.table_to_entry_insertion_count[table_name]}\n"
            )

        return (
            f"================================= RuntimeStates ================================\n"
            f"-------------------------------- table counters --------------------------------\n"
            f"{table_count_str}\n"
            f"---------------------------------- table sizes ----------------------------------\n"
            f"{table_size_str}\n"
            f"-------------------------- table entry insertion count --------------------------\n"
            f"{table_insert_str}\n\n"
            f"------ total memory: {self.total_memory}\n"
            f"------ total entry insertion bandiwdth: {self.total_entry_insertion_bandwidth}\n"
        )
