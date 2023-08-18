from abc import ABC, abstractmethod
from typing import Any, Dict, Union
from commons.constants import ActionType, OptimizedType
from commons.types import ActionInfoMap
from graph_optimizer.metadata import (
    CacheMetadata,
    ExtensionMetadata,
    GroupCacheMetadata,
    MergeMetadata,
    SoftcopyMetadata,
)
from ir.ir_node import IrNode, Root
from ir.general_table import GeneralTable
from ir.match_key import MatchType
from commons.base_logging import logger


class OptTable(GeneralTable, ABC):
    """Optimizer-generated tables"""

    @abstractmethod
    def is_to_reconnect(self, prev_node: Union[Root, IrNode]) -> bool:
        raise NotImplementedError(f"The class of {self.name} needs to implement is_to_reconnect")


class ExtensionTable(OptTable):
    def is_to_reconnect(self, prev_node: Union[Root, IrNode]) -> bool:
        # For extension tables, no need to reconnect
        return False

    def update_mapping(self, cxt_id: int, mapping: Dict[str, Any]) -> None:
        table_mapping = mapping["tables"]
        assert isinstance(self.optimized_metadata, ExtensionMetadata), (
            f"Optimized metadata for ExtensionTable {self.name} can only be "
            f"ExtensionMetadata, but we got {self.optimized_metadata.__class__.__name__}"
        )
        original_table = self.optimized_metadata.extended_table

        if original_table.name not in table_mapping:
            table_mapping[original_table.name] = {}

        assert "migrated" not in table_mapping[original_table.name], (
            f"Only one extension table will set up the 'migrated' field of "
            f"the original table, but table {original_table.name} has been "
            f"set with this field twice"
        )
        table_mapping[original_table.name]["migrated"] = {
            "cxt": cxt_id,
            "actions": self.action_names,
        }


class SoftcopyTable(OptTable):
    def is_to_reconnect(self, prev_node: Union[Root, IrNode]) -> bool:
        # For copy tables, reconnect previous table if it is in ARM or if it is
        # Root
        if isinstance(prev_node, Root) or prev_node.optimized_type == OptimizedType.SW_STEERING:
            if not isinstance(prev_node, Root):
                assert isinstance(prev_node, GeneralTable), (
                    f"Only Table can be assigned to ARM, but we got "
                    f"{prev_node} with class {prev_node.__class__.__name__}"
                )
            return True
        return False

    def update_mapping(self, cxt_id: int, mapping: Dict[str, Any]) -> None:
        table_mapping = mapping["tables"]
        assert isinstance(self.optimized_metadata, SoftcopyMetadata), (
            f"Optimized metadata for SoftcopyTable {self.name} can only be "
            f"SoftcopyMetadata, but we got {self.optimized_metadata.__class__.__name__}"
        )
        original_table = self.optimized_metadata.copied_table

        if original_table.name not in table_mapping:
            table_mapping[original_table.name] = {}

        assert "copied" not in table_mapping[original_table.name], (
            f"Only one softcopy table will set up the 'copied' field of "
            f"the original table, but table {original_table.name} has been "
            f"set with this field twice"
        )
        table_mapping[original_table.name]["copied"] = {
            "cxt": cxt_id,
        }


class CacheTable(OptTable):
    def is_to_reconnect(self, prev_node: Union[Root, IrNode]) -> bool:
        # For cache tables, reconnect previous node if previous node is not
        # the CacheTable itself
        if isinstance(prev_node, CacheTable):
            assert isinstance(self.optimized_metadata, CacheMetadata) or isinstance(
                self.optimized_metadata, GroupCacheMetadata
            ), (
                f"Optimized metadata for CacheTable {self.name} can only be "
                f"CacheMetadata, but we got {self.optimized_metadata.__class__.__name__}"
            )
            if prev_node.name == (self.optimized_metadata.cached_tables[0].opt_table.name):
                return False

        assert isinstance(self.optimized_metadata, CacheMetadata) or isinstance(
            self.optimized_metadata, GroupCacheMetadata
        ), (
            f"Optimized metadata for CacheTable {self.name} can only be "
            f"CacheMetadata, but we got {self.optimized_metadata.__class__.__name__}"
        )
        # Also if previous node is one of the cached tables of this cache table,
        # it means the current cached table is not the first cached table, so we
        # shouldn't reconnect the previous node to the cache table
        if prev_node in self.optimized_metadata.cached_tables:
            return False

        return True

    def update_mapping(self, cxt_id: int, mapping: Dict[str, Any]) -> None:
        cache_table_mapping = mapping["cache_tables"]
        table_mapping = mapping["tables"]
        if isinstance(self.optimized_metadata, GroupCacheMetadata):
            logger.warning(f"The group cache table is resuing the cache table functions")
            return

        assert isinstance(self.optimized_metadata, CacheMetadata), (
            f"Optimized metadata for CacheTable {self.name} can only be "
            f"CacheMetadata, but we got {self.optimized_metadata.__class__.__name__}"
        )
        assert self.name not in cache_table_mapping, f"Two cache tables have the same table name {self.name}"
        cache_table_mapping[self.name] = {
            "name": self.name,
            "cxt": cxt_id,
            "cached_tables": [original_table.name for original_table in self.optimized_metadata.cached_tables],
        }
        combined_table_list = self.optimized_metadata.cached_tables
        for original_table in combined_table_list:
            if original_table.name not in table_mapping:
                table_mapping[original_table.name] = {}

            assert "cached" not in table_mapping[original_table.name], (
                f"Only one cache table will set up the 'cached' field of "
                f"the original table, but table {original_table.name} has been "
                f"set with this field twice"
            )
            table_mapping[original_table.name]["cached"] = {
                "cxt": cxt_id,
                "cache_table": self.name,
            }

    def change_cached_table_actions(self) -> None:
        """Iterate through all cached tables and change their actions to record
        path at runtime when cache miss, and let last cached table execute entry
        insertion command"""
        assert isinstance(self.optimized_metadata, CacheMetadata), (
            f"Optimized metadata for CacheTable {self.name} can only be "
            f"CacheMetadata, but we got {self.optimized_metadata.__class__.__name__}"
        )
        cached_tables = self.optimized_metadata.cached_tables
        # We need to prepend install_cache_entry primitive first, so that it is
        # executed after recording path primitives
        cached_tables[-1].add_insert_cache_entry_to_all_actions(self)
        for cached_table in cached_tables:
            cached_table.add_record_path_to_all_actions()


class MergeTable(OptTable):
    def is_to_reconnect(self, prev_node: IrNode) -> bool:
        # For merge tables, reconnect previous node if previous node is not
        # the MergeTable itself
        if isinstance(prev_node, MergeTable):
            assert isinstance(self.optimized_metadata, MergeMetadata), (
                f"Optimized metadata for MergeTable {self.name} can only be "
                f"MergeMetadata, but we got {self.optimized_metadata.__class__.__name__}"
            )
            if prev_node.name == (self.optimized_metadata.merged_tables[0].opt_table.name):
                return False

        assert isinstance(self.optimized_metadata, MergeMetadata), (
            f"Optimized metadata for MergeTable {self.name} can only be "
            f"MergeMetadata, but we got {self.optimized_metadata.__class__.__name__}"
        )
        # Also if previous node is one of the merged tables of this merge table,
        # it means the current merged table is not the first merged table, so we
        # shouldn't reconnect the previous node to the merge table
        if prev_node in self.optimized_metadata.merged_tables:
            return False

        return True

    def update_mapping(self, cxt_id: int, mapping: Dict[str, Any]) -> None:
        merge_table_mapping = mapping["merge_tables"]
        table_mapping = mapping["tables"]
        assert isinstance(self.optimized_metadata, MergeMetadata), (
            f"Optimized metadata for MergeTable {self.name} can only be "
            f"MergeMetadata, but we got {self.optimized_metadata.__class__.__name__}"
        )
        assert self.name not in merge_table_mapping, f"Two merge tables have the same table name {self.name}"
        merge_table_mapping[self.name] = {
            "name": self.name,
            "cxt": cxt_id,
            "merged_tables": [original_table.name for original_table in self.optimized_metadata.merged_tables],
            "match_type": self.match_type._name_,
        }
        combined_table_list = self.optimized_metadata.merged_tables
        for original_table in combined_table_list:
            if self.match_type == MatchType.TERNARY:
                # In this case, the original tables won't exist in the pipeline,
                # so we need to add the mapping for them here
                # 999 to mark them as not in pipeline. I don't use -1 because
                # cxt_id is an uint in bmv2
                original_table.update_mapping(999, mapping)
            if original_table.name not in table_mapping:
                table_mapping[original_table.name] = {}

            assert "merged" not in table_mapping[original_table.name], (
                f"Only one merge table will set up the 'merged' field of "
                f"the original table, but table {original_table.name} has been "
                f"set with this field twice"
            )
            table_mapping[original_table.name]["merged"] = {
                "cxt": cxt_id,
                "merge_table": self.name,
            }

            assert "key_length" not in table_mapping[original_table.name], (
                f"Only one merge table will set up the 'key_length' field of "
                f"the original table, but table {original_table.name} has been "
                f"set with this field twice"
            )
            table_mapping[original_table.name]["key_length"] = [
                match_key._get_key_length(self.irgraph) for match_key in original_table.keys
            ]
