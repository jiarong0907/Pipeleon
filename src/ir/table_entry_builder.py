from __future__ import annotations
from abc import ABC, abstractmethod
from copy import deepcopy
import itertools
from typing import TYPE_CHECKING, List

from commons.base_logging import logger
from graph_optimizer.metadata import MergeMetadata
from ir.match_key import MatchKey, MatchType
from ir.table_entry import (
    EntryMatchKeyParam,
    ExactEntryMatchKeyParam,
    LpmEntryMatchKeyParam,
    TableEntry,
    TernaryEntryMatchKeyParam,
)

if TYPE_CHECKING:
    from ir.table import Table
    from ir.opt_table import OptTable
    from ir.irgraph import IrGraph
    from ir.table_entry import EntryMatchKey
    from commons.types import ActionData, ActionName


class GeneralTableEntryBuilder(ABC):
    """The builder for building the entries from source table to target table.

    This builder can be used to rebuild the original table's entries when it was
    deleted by previous optimization rounds, or build derived entries for
    optimization tables based on original table

    Args:
        - source_table: The unoptimized table. For cache and merge, this is the
            first table in the segment
        - target_table: The optimizer created table.
    """

    def __init__(self, irgraph: IrGraph, source_table: Table, target_table: OptTable):
        self._irgraph = irgraph
        self._source_table = source_table
        self._target_table = target_table

    @property
    def irgraph(self) -> IrGraph:
        return self._irgraph

    @property
    def source_table(self) -> Table:
        return self._source_table

    @property
    def target_table(self) -> OptTable:
        return self._target_table

    @abstractmethod
    def build_entries(self) -> List[TableEntry]:
        """Build entries based on the source table's entries and store them in
        the target table's entries

        Return:
            The created and stored entries
        """
        raise NotImplementedError(f"build_entries of {self.__class__.__name__} should be implemented")


class TableEntryBuilder(GeneralTableEntryBuilder):
    def build_entries(self) -> List[TableEntry]:
        assert self._source_table is self._target_table, (
            f"User table's entry builder should have the same source table "
            f"and target table, but we got {self._source_table} as source, "
            f"{self._target_table} as target"
        )
        return self._target_table.entries


class ExtensionTableEntryBuilder(GeneralTableEntryBuilder):
    def build_entries(self) -> List[TableEntry]:
        assert False, (
            f"We don't expect this code to be executed "
            f"because extension table should be prepared "
            f"at compile time and never changed at "
            f"runtime by flexcore"
        )


class SoftcopyTableEntryBuilder(GeneralTableEntryBuilder):
    def build_entries(self) -> List[TableEntry]:
        logger.debug(f"Building entries from {self._source_table.name} to " f"{self._target_table.name}")
        logger.debug(f"Source table has entries\n{self._source_table.entries}")
        self._target_table.entries = deepcopy(self._source_table.entries)
        logger.debug(f"Target table now has entries\n{self._target_table.entries}")
        return self._target_table.entries


class CacheTableEntryBuilder(GeneralTableEntryBuilder):
    def build_entries(self) -> List[TableEntry]:
        logger.info("Cache table entries will be populated at runtime.")
        self._target_table.entries = []
        return self._target_table.entries


class GroupCacheTableEntryBuilder(GeneralTableEntryBuilder):
    def build_entries(self) -> List[TableEntry]:
        logger.info("Cache table entries will be populated at runtime.")
        return []


class MergeTableEntryBuilder(GeneralTableEntryBuilder):
    def _get_exact_key_mask(self, key: str) -> str:
        """Generate a mask for an exact key. It is done by making every binary bit to 1
        for the length of the match key, and then convert it to hex without leading 0x.
        """
        # binary_key = bin(int(key, 16))[2:] # remove the leading '0b'
        # bit_length = len(binary_key)
        # mask:str = hex(int('1'*bit_length, 2))[2:] # remove the leading '0x'
        # TODO: This assumes the key length is x times of 4 bits.
        mask: str = "f" * len(key)  # remove the leading '0x'
        return mask

    def _get_lpm_key_mask(self, table_match_key: MatchKey, prefix_length: int) -> str:
        """Generate a mask for a lpm entry."""
        # TODO: This assumes the key length is x times of 4 bits.
        assert table_match_key.match_type == MatchType.LPM, f"The table match key must be LPM."
        key_length = table_match_key._get_key_length(self.irgraph)
        assert key_length >= prefix_length, f"The required prefix length is longer than the match key length."
        assert key_length % 4 == 0, f"For now, we assume key length is x times of 4 bits, but we got " f"{key_length}"
        mask_str = "1" * prefix_length + "0" * (key_length - prefix_length)
        mask_str = hex(int(mask_str, 2))[2:]
        if mask_str == "0":
            mask_str = "0" * (key_length // 4)
        return mask_str

    def _get_merged_entry_priority(
        self, merged_table_type: MatchType, cross_producted_entries: List[TableEntry]
    ) -> int:
        if merged_table_type == MatchType.TERNARY:
            priorities: List[int] = [*[e.priority for e in cross_producted_entries]]
            return sum(priorities)
        else:
            return -1

    def _convert_all_entry_keys_to_ternary(self, table: Table, entries: List[TableEntry]) -> List[TableEntry]:
        """Convert all entry keys in the entry to ternary keys. This is needed by
        adding a default rule for table merge. Accordingly, the merged table's match
        keys should also be converted to ternary.
        """
        new_entries: List[TableEntry] = []
        table_match_keys: List[MatchKey] = table.keys
        for entry in entries:
            is_ternary = False
            entry_match_keys = entry.match_key
            new_match_keys: List[EntryMatchKeyParam] = []
            for i in range(len(entry_match_keys)):
                entry_mkey = entry_match_keys[i]
                if isinstance(entry_mkey, TernaryEntryMatchKeyParam):
                    new_match_keys.append(entry_mkey)
                    is_ternary = True
                    continue
                assert isinstance(entry_mkey, ExactEntryMatchKeyParam) or isinstance(
                    entry_mkey, LpmEntryMatchKeyParam
                ), (f"We support only merging exact, lpm and ternary tables, " f"but we got {type(entry_mkey)}")
                if isinstance(entry_mkey, ExactEntryMatchKeyParam):
                    mask = self._get_exact_key_mask(entry_mkey.key)
                elif isinstance(entry_mkey, LpmEntryMatchKeyParam):
                    mask = self._get_lpm_key_mask(
                        table_match_key=table_match_keys[i], prefix_length=entry_mkey.prefix_length
                    )
                else:
                    raise ValueError(f"Unepected match key instance type {type(entry_mkey)}")
                new_match_keys.append(TernaryEntryMatchKeyParam(type="TERNARY", key=entry_mkey.key, mask=mask))
            new_entries.append(
                TableEntry(
                    action_name=entry.action_name,
                    action_data=entry.action_data,
                    match_key=new_match_keys,
                    # 1 is reserved for the default entry
                    priority=2 if not is_ternary else entry.priority,
                )
            )
        return new_entries

    def _add_default_ternary_entry(self, table: Table, all_ternary_entries: List[TableEntry]) -> List[TableEntry]:
        """Add a default ternary entry with lowest priority for a table to be merged.
        This is done by copying the first entry in the table and changing all the masks
        to match anything.
        """

        default_action_name = table.default_action_name
        default_action_param = table.default_action_param
        # default_entry_keys:EntryMatchKey = deepcopy(all_ternary_entries[0].match_key)
        # for ekey in default_entry_keys:
        #     assert isinstance(ekey, TernaryEntryMatchKeyParam), (
        #         f"All entry keys must be ternary because we have converted this table to ternary."
        #     )
        #     ekey.key = "0"
        #     ekey.mask = "0"
        default_entry_keys: EntryMatchKey = []
        for table_match_key in table.keys:
            key_length = table_match_key._get_key_length(table.irgraph)
            # TODO: This assumes the key length is x times of 4 bits.
            assert key_length % 4 == 0, (
                f"For now, we assume key length is x times of 4 bits, but " f"we got {key_length}"
            )
            if table_match_key.match_type == MatchType.EXACT:
                mask = "0" * (key_length // 4)
            elif table_match_key.match_type == MatchType.LPM:
                mask = self._get_lpm_key_mask(
                    table_match_key=table_match_key,
                    prefix_length=0,
                )
            else:
                assert table_match_key.match_type == MatchType.TERNARY, (
                    f"We only support EXACT, LPM, TERNARY keys of merged "
                    f"tables when creating their merge table, but we got "
                    f"{table_match_key.match_type._name_}"
                )
                mask = "0" * (key_length // 4)
            default_entry_keys.append(
                TernaryEntryMatchKeyParam(
                    type="TERNARY",
                    key="0" * (key_length // 4),
                    mask=mask,
                )
            )

        min_priority = (
            min([e.priority for e in all_ternary_entries])
            if all_ternary_entries != None and all_ternary_entries != []
            else 2
        )
        assert (
            min_priority > 1
        ), f"The min priority is already the minimal number, we cannot add a default entry any more"

        all_ternary_entries.append(
            TableEntry(
                action_name=default_action_name,
                action_data=default_action_param,
                match_key=default_entry_keys,
                priority=1,  # TODO: is 1 the minimal priority?
            )
        )
        return all_ternary_entries

    def _cross_product_entries(
        self,
        merged_table_type: MatchType,
        group1: List[TableEntry],
        group2: List[TableEntry],
    ) -> List[TableEntry]:
        """Merge two groups of entries by cross-product directly."""
        # itertools.product(*[[1,2],[3,4],[5,6]]) ==> [(1, 3, 5), (1, 3, 6),...
        cross_products = itertools.product(*[group1, group2])
        # create merged entries
        merged_entries: List[TableEntry] = []
        for cro_pro in cross_products:
            action_names: List[ActionName] = [*[e.action_name for e in cro_pro]]
            # TODO: check whether the order of the action name is correct.
            merged_action_name = "merged_" + "_".join(action_names)
            action_data: List[ActionData] = list(itertools.chain(*[e.action_data for e in cro_pro]))
            match_keys: EntryMatchKey = list(itertools.chain(*[e.match_key for e in cro_pro]))
            merged_priority = self._get_merged_entry_priority(merged_table_type, list(cro_pro))
            merged_entries.append(
                TableEntry(
                    action_name=merged_action_name,
                    action_data=action_data,
                    match_key=match_keys,
                    priority=merged_priority,
                )
            )
        return merged_entries

    def _merge_two_tables_entries(self, table1: Table, table2: Table) -> List[TableEntry]:
        """Merge entries from the provided two tables and return the merged entries."""
        group1: List[TableEntry] = table1.entries
        type1: MatchType = table1.match_type
        group2: List[TableEntry] = table2.entries
        type2: MatchType = table2.match_type

        # Exact and LPM can be merged by cross-product directly
        # For this kind of merge, the original tables will be reserved.
        if (
            (type1 == MatchType.EXACT and type2 == MatchType.EXACT)
            or (type1 == MatchType.EXACT and type2 == MatchType.LPM)
            or (type1 == MatchType.LPM and type2 == MatchType.EXACT)
        ):
            return self._cross_product_entries(MatchType.LPM, group1, group2)

        # We don't allow merging two LPM tables
        if type1 == MatchType.LPM and type2 == MatchType.LPM:
            raise ValueError("Two LPM table merge is not allowed.")

        # If one of the table is ternary, we need to do the following:
        # 1) convert the non-ternary table to ternary table. Note that we also need to convert
        # the non-ternary keys in the ternary table to ternary keys.
        # 2) add a default entry with lowest priority for both tables
        # 3) merge them by cross-product
        # For this kind of merge, the original tables will be deleted
        if (
            (type1 == MatchType.EXACT and type2 == MatchType.TERNARY)
            or (type1 == MatchType.TERNARY and type2 == MatchType.EXACT)
            or (type1 == MatchType.LPM and type2 == MatchType.TERNARY)
            or (type1 == MatchType.TERNARY and type2 == MatchType.LPM)
            or (type1 == MatchType.TERNARY and type2 == MatchType.TERNARY)
        ):
            group1 = self._convert_all_entry_keys_to_ternary(table1, group1)
            group2 = self._convert_all_entry_keys_to_ternary(table2, group2)
            self._add_default_ternary_entry(table1, group1)
            self._add_default_ternary_entry(table2, group2)
            return self._cross_product_entries(MatchType.TERNARY, group1, group2)

        raise ValueError(f"Unexpected match types! {type1}, {type2}")

    def build_entries(self) -> List[TableEntry]:
        optimized_metadata = self.source_table.optimized_metadata
        assert optimized_metadata != None, f"optimized_metadata has not been set, cannot merge table entries"
        assert isinstance(optimized_metadata, MergeMetadata), f"optimized_metadata is not an instance of MergeMetadata"

        tables_to_merge = optimized_metadata.merged_tables
        assert len(tables_to_merge) == 2, f"We support merging only two tables for now"

        return self._merge_two_tables_entries(table1=tables_to_merge[0], table2=tables_to_merge[1])
