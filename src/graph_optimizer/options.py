from dataclasses import dataclass
import os
import time
from typing import Any, Dict, List, Optional, Union
from graph_optimizer.pipelet import Pipelet, PipeletGroup
from commons.types import Bytes
from ir.irgraph_pipe import IrGraphPipe, IrNode


@dataclass
class ReorderOption:
    """A wrapper for a reorder plan

    The new_table_pos records the new positions for tables in this pipelet.
    For example, table at location 0 will be reordered to location 1 if list[1] is 0.
    """

    new_table_pos: List[int]

    def __str__(self) -> str:
        return f">>>>>{self.__class__.__name__}\n" f"new_table_pos: {self.new_table_pos}"


@dataclass
class SegmentOptimizationOption:
    """A parent class for all segment-based optimizations wrappers

    Each plan has two numbers [start_table_id, length], e.g., option [0, 3]
    means performing the segment-based optimization on table 1 to table 3
    """

    start_table_id: int
    length: int

    def __str__(self) -> str:
        return f"start_table_id: {self.start_table_id}, length: {self.length}\n"


@dataclass
class SoftmoveOption(SegmentOptimizationOption):
    """A wrapper for a softmove plan

    Each plan has two numbers [start_table_id, length], e.g., option [0, 3]
    means copying table 1 to table 3 to ARM
    """

    def __str__(self) -> str:
        return f">>>>>{self.__class__.__name__}\n" f"{super().__str__()}"


@dataclass
class SoftcopyOption(SegmentOptimizationOption):
    """A wrapper for a softcopy plan

    Each plan has two numbers [start_table_id, length], e.g., option [0, 3]
    means copying table 1 to table 3 to ARM
    """

    def __str__(self) -> str:
        return f">>>>>{self.__class__.__name__}\n" f"{super().__str__()}"


@dataclass
class MergeOption(SegmentOptimizationOption):
    """A wrapper for a merge plan

    Each plan has two numbers [start_table_id, length], e.g., option [0, 3]
    means merging table 1 to table 3.
    """

    def __str__(self) -> str:
        return f">>>>>{self.__class__.__name__}\n" f"{super().__str__()}"


@dataclass
class CacheOption(SegmentOptimizationOption):
    """A wrapper for a cache plan

    Each plan has two numbers [start_table_id, length], e.g., option [0, 3]
    means caching table 1 to table 3.
    """

    def __str__(self) -> str:
        return f">>>>>{self.__class__.__name__}\n" f"{super().__str__()}"


@dataclass
class GroupOptimizationOption:
    """A parent class for all group optimizations wrappers

    This wrapper has only the information of the PipeletGroup because we consider only
    whole group merge or whole group cache.
    """

    root: IrNode
    sink: IrNode
    size: int
    pipelets: List[Pipelet]

    def __str__(self) -> str:
        return (
            f"root: {self.root.name}, sink: {self.sink.name}, size: {self.size}\n"
            f"pipelets(roots): {[p.root.name for p in self.pipelets]}"
        )


@dataclass
class GroupMergeOption(GroupOptimizationOption):
    """A wrapper for a group merge plan"""

    def __str__(self) -> str:
        return f">>>>>{self.__class__.__name__}\n" f"{super().__str__()}"


@dataclass
class GroupCacheOption(GroupOptimizationOption):
    """A wrapper for a group cache plan"""

    def __str__(self) -> str:
        return f">>>>>{self.__class__.__name__}\n" f"{super().__str__()}"


@dataclass
class AggregatedOption:
    """Parent class of PipeletOption and PipeletGroupOption. Used to provide a unified
    object for the DP algorithm
    """

    mcost: Bytes  # memory cost
    icost: int  # entry insertion bandwidth cost
    lgain: float  # latency gain
    tgain: float  # throughput gain

    @property
    def irgraph_pipe(self) -> IrGraphPipe:
        raise NotImplementedError()


CombinedOptionType = Union[SoftcopyOption, SoftmoveOption, MergeOption, CacheOption]
OPTION_TYPE_STR_TO_ABRV = {
    "SoftcopyOption": "SC",
    "SoftmoveOption": "SM",
    "MergeOption": "M",
    "CacheOption": "C",
}
GroupOptionType = Union[GroupMergeOption, GroupCacheOption]


class PipeletOption(AggregatedOption):
    """A wrapper for a combined optimization plan of a pipelet. Each pipelet
    could have a list of PipeletOption, each item is a potential optimization plan.
    """

    def __init__(
        self,
        pipelet: Pipelet,
        new_order: ReorderOption,
        combined_options: Optional[List[CombinedOptionType]],
        mcost: Bytes = -1,
        icost: int = -1,
        lgain: float = -1,
        tgain: float = -1,
    ):
        super().__init__(mcost, icost, lgain, tgain)
        self._pipelet = pipelet
        self._new_order = new_order
        self._combined_options = combined_options

    @property
    def pipelet(self) -> Pipelet:
        return self._pipelet

    @pipelet.setter
    def pipelet(self, new_pipelet: Pipelet):
        self._pipelet = new_pipelet

    @property
    def new_order(self) -> ReorderOption:
        return self._new_order

    @new_order.setter
    def new_order(self, new_new_order: ReorderOption):
        self._new_order = new_new_order

    @property
    def combined_options(self) -> Optional[List[CombinedOptionType]]:
        return self._combined_options

    @combined_options.setter
    def combined_options(self, new_combined_options: List[CombinedOptionType]):
        self._ncombined_options = new_combined_options

    @property
    def irgraph_pipe(self) -> IrGraphPipe:
        return self.pipelet.irgraph_pipe

    def info(self) -> Dict[str, Any]:
        softcopy = []
        softmove = []
        merge = []
        cache = []
        if self.combined_options != None:
            for option in self.combined_options:
                if isinstance(option, SoftcopyOption):
                    softcopy.append((option.start_table_id, option.length))
                elif isinstance(option, SoftmoveOption):
                    softmove.append((option.start_table_id, option.length))
                elif isinstance(option, MergeOption):
                    merge.append((option.start_table_id, option.length))
                elif isinstance(option, CacheOption):
                    cache.append((option.start_table_id, option.length))
                else:
                    raise Exception("Unexpected optimization type!")
        return {
            "pipelet_start": self.pipelet.root.name,
            "pipelet_length": self.pipelet.length,
            "mcost": self.mcost,
            "icost": self.icost,
            "lgain": self.lgain,
            "tgain": self.tgain,
            "Reorder": self.new_order.new_table_pos,
            "Softcopy": softcopy,
            "Softmove": softmove,
            "Merge": merge,
            "Cache": cache,
        }

    def _option_str(self, verbose=True) -> str:
        original_table_names = self.pipelet.table_names
        new_order_table_names = [original_table_names[i] for i in self.new_order.new_table_pos]
        option_str = ""
        if self.combined_options != None:
            for op in self.combined_options:
                plan_names = [new_order_table_names[i] for i in range(op.start_table_id, op.start_table_id + op.length)]
                if verbose:
                    option_str += f"{str(op).rstrip()} ==> {str(plan_names)}\n"
                else:
                    option_str += f"{OPTION_TYPE_STR_TO_ABRV[op.__class__.__name__]} {'|'.join(plan_names)} "
        return option_str[:-1]  # remove last \n or ' '

    def __str__(self) -> str:
        num_combined_options = 0 if self.combined_options == None else len(self.combined_options)
        original_table_names = self.pipelet.table_names
        new_order_table_names = [original_table_names[i] for i in self.new_order.new_table_pos]
        return (
            f"=================================\n"
            f"start_node_name: {self.pipelet.root.name}\n"
            f"pipelet_length: {self.pipelet.length}\n"
            f"num_combined_options: {num_combined_options}\n"
            f"mcost: {self.mcost}\n"
            f"icost: {self.icost}\n"
            f"lgain: {self.lgain}\n"
            f"tgain: {self.tgain}\n"
            f"new_order: {self.new_order.new_table_pos} ==> {new_order_table_names}\n"
            f"{self._option_str()}\n"
        )

    def _log_str(self, print_cost: bool = False, verbose=True) -> str:
        num_combined_options = 0 if self.combined_options == None else len(self.combined_options)
        original_table_names = self.pipelet.table_names
        new_order_table_names = [original_table_names[i] for i in self.new_order.new_table_pos]
        if print_cost:
            return (
                f"=================================\n"
                f"start_node_name: {self.pipelet.root.name}\n"
                f"pipelet_length: {self.pipelet.length}\n"
                f"num_combined_options: {num_combined_options}\n"
                f"mcost: {self.mcost}\n"
                f"icost: {self.icost}\n"
                f"lgain: {self.lgain}\n"
                f"tgain: {self.tgain}\n"
                f"new_order: {self.new_order.new_table_pos} ==> {new_order_table_names}\n"
                f"{self._option_str()}\n"
            )
        else:
            if verbose:
                return (
                    f"=================================\n"
                    f"start_node_name: {self.pipelet.root.name}\n"
                    f"pipelet_length: {self.pipelet.length}\n"
                    f"num_combined_options: {num_combined_options}\n"
                    f"new_order: {self.new_order.new_table_pos} ==> {new_order_table_names}\n"
                    f"{self._option_str()}\n"
                )
            else:
                ret = ""
                if self.new_order.new_table_pos != list(range(self.pipelet.length)):
                    ret += f"R {'|'.join(new_order_table_names)} "
                ret += self._option_str(verbose=verbose)
                return ret


@dataclass
class PipeletGroupOption(AggregatedOption):
    """A wrapper for a combined optimization plan of a pipelet group. Each pipelet group
    could have a list of PipeletOption, and one group merge/cache option.
    """

    def __init__(
        self,
        pipelet_group: PipeletGroup,
        pipelet_options: Optional[List[PipeletOption]],
        group_options: Optional[List[GroupOptionType]],
        mcost: Bytes = -1,
        icost: int = -1,
        lgain: float = -1,
        tgain: float = -1,
    ):
        super().__init__(mcost, icost, lgain, tgain)
        self._pipelet_group = pipelet_group
        self._pipelet_options = pipelet_options
        self._group_options = group_options

    @property
    def pipelet_group(self) -> PipeletGroup:
        return self._pipelet_group

    @pipelet_group.setter
    def pipelet_group(self, new_pipelet_group: PipeletGroup):
        self._pipelet_group = new_pipelet_group

    @property
    def pipelet_options(self) -> Optional[List[PipeletOption]]:
        return self._pipelet_options

    @pipelet_options.setter
    def pipelet_options(self, new_pipelet_options: List[PipeletOption]):
        self._pipelet_options = new_pipelet_options

    @property
    def group_options(self) -> Optional[List[GroupOptionType]]:
        return self._group_options

    @group_options.setter
    def group_options(self, new_group_options: List[GroupOptionType]):
        self._group_options = new_group_options

    @property
    def irgraph_pipe(self) -> IrGraphPipe:
        return self.pipelet_group.irgraph_pipe

    def __str__(self) -> str:
        pipelet_option_str = ""
        if self.pipelet_options != None:
            for po in self.pipelet_options:
                pipelet_option_str += f"{str(po)}\n"

        group_option_str = ""
        if self.group_options != None:
            for go in self.group_options:
                group_option_str += f"{str(go)}\n"

        return (
            f"=================================\n"
            f"{str(self.pipelet_group)}\n"
            f"{pipelet_option_str}\n"
            f"{group_option_str}\n"
            f"mcost: {self.mcost}\n"
            f"icost: {self.icost}\n"
            f"lgain: {self.lgain}\n"
            f"tgain: {self.tgain}\n"
        )


@dataclass
class ProgramOption:
    """A wrapper for an optimization plan of the whole program. This is used to
    compute the best plan using dynamic programming.
    """

    option: List[AggregatedOption]
    # The latency gain or throughput gain so far. Used to store the intermediate
    # result in the dynamic programming algorithm.
    gain: float

    @property
    def num_option(self) -> int:
        return len(self.option)

    @property
    def irgraph_pipe(self) -> Optional[IrGraphPipe]:
        if self.option is None:
            return
        return self.option[0].irgraph_pipe

    def __str__(self) -> str:
        pipeletoption_str = ""
        for op in self.option:
            pipeletoption_str += str(op)
        return (
            f"================================= ProgramOption ================================\n"
            f"gain: {self.gain}\n"
            f"num_of_options: {self.num_option}\n"
            f"{pipeletoption_str}\n"
        )

    def _log_str(self, round, verbose=True) -> str:
        if verbose:
            pipeletoption_str = ""
            for op in self.option:
                assert isinstance(op, PipeletOption)
                pipeletoption_str += op._log_str(print_cost=False)
            return (
                f"================================= Round {round} ================================\n"
                f"gain: {self.gain}\n"
                f"num_of_options: {self.num_option}\n"
                f"{pipeletoption_str}\n"
            )
        else:
            ret = f"{int(time.time() * 1000)} {self.gain} {self.num_option} "
            for op in self.option:
                assert isinstance(op, PipeletOption)
                ret += op._log_str(print_cost=False, verbose=verbose) + " "
            return ret + "\n"

    def log_dump(self, round: int, out_path: str):
        if round == 0:
            with open(out_path, "w") as f:
                f.write(self._log_str(round, verbose=False))
        else:
            with open(out_path, "a") as f:
                f.write(self._log_str(round, verbose=False))
