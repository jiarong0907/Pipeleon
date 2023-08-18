from __future__ import annotations
from dataclasses import dataclass
from typing import List, TYPE_CHECKING, Union

if TYPE_CHECKING:
    from ir.table import Table
    from ir.ir_node import Sink
    from graph_optimizer.pipelet import PipeletGroup
    from ir.condition import Condition


@dataclass(frozen=True)
class OptimizedMetadata:
    """A metadata stores information needed by JsonDeployer.
    Will be populated after the optimization algorithm has generated the best plan.
    """

    start_table_id: int
    length: int

    def __str__(self) -> str:
        return f"start_table_id: {self.start_table_id}, length: {self.length}\n"


@dataclass(frozen=True)
class ExtensionMetadata(OptimizedMetadata):
    """ "A metadata stores information of extension needed by JsonDeployer"""

    extended_table: Table


@dataclass(frozen=True)
class SoftmoveMetadata(OptimizedMetadata):
    """ "A metadata stores information of softmove needed by JsonDeployer"""

    pass


@dataclass(frozen=True)
class SoftcopyMetadata(OptimizedMetadata):
    """ "A metadata stores information of softcopy needed by JsonDeployer"""

    copied_table: Table


@dataclass(frozen=True)
class MergeMetadata(OptimizedMetadata):
    """ "A metadata stores information of merge needed by JsonDeployer"""

    merged_tables: List[Table]


@dataclass(frozen=True)
class CacheMetadata(OptimizedMetadata):
    """ "A metadata stores information of cache needed by JsonDeployer"""

    cached_tables: List[Table]


@dataclass(frozen=True)
class GroupOptimizedMetadata:
    """A metadata stores information needed by JsonDeployer.
    Will be populated after the optimization algorithm has generated the best plan.
    """

    pipe_grp: PipeletGroup
    root: Union[Table, Condition]
    sink: Union[Table, Condition, Sink]

    def __str__(self) -> str:
        return f"root_name: {self.pipe_grp.root.name}, " f"sink_name: {self.pipe_grp.sink.name}\n"


@dataclass(frozen=True)
class GroupCacheMetadata(GroupOptimizedMetadata):
    """ "A metadata stores information of cache needed by JsonDeployer"""

    cached_tables: List[Union[Table, Condition]]
