from dataclasses import dataclass
import math
from typing import List, Tuple, Union
import networkx as nx

from commons.constants import DeviceTargetType, OptimizedType
from commons.metric import MetricParams
from commons.types import Bytes, NanoSec, TableName
from commons.base_logging import logger

from ir.irgraph_pipe import IrGraphPipe
from ir.table import Table
from ir.condition import Condition
from ir.ir_node import Sink


@dataclass
class Pipelet:
    irgraph_pipe: IrGraphPipe
    root: Table  # part of the pipelet
    length: int

    def __hash__(self):
        return hash((self.root.name, self.length))

    def __eq__(self, other):
        return self.root.name == other.root.name and self.length == other.length

    @property
    def sink(self) -> Table:
        """The last table in this pipelet (belongs to the pipelet)"""
        return self.tables[-1]

    @property
    def tables(self) -> List[Table]:
        """Collect all tables in the pipelet"""
        next_start = self.root
        tables = []
        for i in range(0, self.length):
            assert isinstance(next_start, Table), (
                f"All nodes in a pipelet should be a Table, but we got"
                f" a {next_start.__class__.__name__} node: {next_start}"
            )
            tables.append(next_start)
            predecessors = list(self.irgraph_pipe.predecessors(next_start))
            assert (len(predecessors) == 1 and i >= 1) or i == 0, (
                f"Node in a pipelet should have a single predecessor, but node "
                f"{next_start} has multiple: {predecessors}"
            )
            successors = list(self.irgraph_pipe.successors(next_start))
            assert len(successors) == 1 or self.length == 1, (
                f"Node in a pipelet should have a single successor, but node "
                f"{next_start} has {len(successors)} successors: {[p.name for p in successors]}"
            )
            # successors could be [] when the only action has exit (early stop)
            if len(successors) > 0:
                next_start = successors[0]
        return tables

    @property
    def table_names(self) -> List[str]:
        """Return table names in order"""
        return [t.name for t in self.tables]

    @property
    def table_target_types(self) -> List[DeviceTargetType]:
        """Iterate the pipelet and return each table's target (DeviceTargetType)."""
        next_start = self.root
        res: List[DeviceTargetType] = []
        for _ in range(0, self.length):
            assert isinstance(next_start, Table), (
                f"All nodes in a pipelet should be a Table, but we got" f" a condition node: {next_start}"
            )
            res.append(next_start.target_type)
            successors = list(self.irgraph_pipe.successors(next_start))
            assert len(successors) == 1, (
                f"Node in a pipelet should have a single successor, but node "
                f"{next_start} has multiple: {successors}"
            )

            next_start = successors[0]
        return res

    @property
    def table_optimized_types(self) -> List[OptimizedType]:
        """Iterate the pipelet and return each table's target (DeviceTargetType)."""
        next_start = self.root
        res: List[OptimizedType] = []
        for _ in range(0, self.length):
            assert isinstance(next_start, Table), (
                f"All nodes in a pipelet should be a Table, but we got" f" a condition node: {next_start}"
            )
            assert (
                next_start.optimized_type != OptimizedType.UNASSIGNED
            ), f"The node {next_start.name} has not been optimized {next_start.optimized_type}"
            res.append(next_start.optimized_type)
            successors = list(self.irgraph_pipe.successors(next_start))
            assert len(successors) == 1, (
                f"Node in a pipelet should have a single successor, but node "
                f"{next_start} has multiple: {successors}"
            )

            next_start = successors[0]
        return res

    def eval(self) -> MetricParams:
        """Evaluate a pipelet where software tables will be ignored
        Used to select top-k pipelets.
        TODO: change to use the igraph_pipe eval?
        """

        assert self.irgraph_pipe.target != None, f"IrGraphPipe {self.irgraph_pipe.name} has not been assigned a target."
        hw_target = self.irgraph_pipe.target.subtargets[DeviceTargetType.HW_STEERING]

        for n in self.tables:
            n.latency_eval = None

        latency_pdf, per_target_load = self.irgraph_pipe._recursive_latency_eval(self.root, self.sink)
        lat_median, lat_p99, lat_average = self.irgraph_pipe._get_latency_stats(latency_pdf)

        prob_pipelet = self.prob_to_it()

        # logger.info(f"name: {self.root.name}")
        # logger.info(f"latency_pdf: {latency_pdf}")
        # logger.info(f"prob_pipelet: {prob_pipelet}")

        measurments = MetricParams(
            p99_latency=int(lat_p99 * prob_pipelet),
            median_latency=int(lat_median * prob_pipelet),
            average_latency=int(lat_average * prob_pipelet),
            inter_packet_gap=None,
            entry_insertion_latency=None,
            entry_insertion_rate=None,
            compute_utilization=None,
            energy_per_packet=None,
            memory_used=None,
            memory_utilization=None,
        )
        return measurments

    def prob_to_it(self) -> float:
        cum_prob = 0  # cumulative probability
        for path in nx.all_simple_paths(self.irgraph_pipe, source=self.irgraph_pipe.root, target=self.root):
            this_prob = 1  # path probability
            for i in range(len(path) - 1):
                node = path[i]
                # times by the branch probability
                if isinstance(node, Condition):
                    found_branch = False
                    for action, prob in node.action_iterator:
                        if action.next_node == path[i + 1].name:
                            this_prob *= prob
                            found_branch = True
                            break
                    assert found_branch, f"Did not found a branch contains the node"
                elif isinstance(node, Table):
                    non_drop_probability = 0
                    found_drop = False
                    # time corresponding prob if this is a switch-case table
                    if node.is_switch_table:
                        found_branch = False
                        for next_tab_name, prob in node._next_table_selector.next_table_to_probability.items():
                            if next_tab_name == path[i + 1].name:
                                this_prob *= prob
                                found_branch = True
                                break
                        assert found_branch, f"Did not found a branch contains the node"
                    # regular table, just case about drop prob
                    else:
                        for action, prob in node.action_iterator:
                            if not action.has_drop:
                                non_drop_probability += prob
                            else:
                                found_drop = True
                        if found_drop:
                            this_prob *= non_drop_probability
                        else:
                            assert math.isclose(non_drop_probability, 1) or math.isclose(non_drop_probability, 0)

            cum_prob += this_prob
        return cum_prob

    @property
    def desc(self) -> Tuple[TableName, int]:
        """Description of this Pipelet, used for testing"""
        return (self.root.name, self.length)

    def __str__(self) -> str:
        return (
            f"-------------------------------- PipeletOption --------------------------------\n"
            f"start_node_name: {self.root.name}\n"
            f"length: {self.length}\n"
        )


@dataclass
class PipeletGroup:
    irgraph_pipe: IrGraphPipe
    root: Union[Table, Condition]  # part of the group
    sink: Union[Table, Condition, Sink]  # not part of the group
    pipelets: List[Pipelet]

    def __hash__(self):
        return hash((self.root.name, self.sink.name, self.size))

    def __eq__(self, other):
        return self.root.name == other.root.name and self.size == other.size and self.sink.name == self.sink.name

    @property
    def tables(self) -> List[Table]:
        res: List[Table] = []
        for p in self.pipelets:
            res += p.tables
        return res

    @property
    def nodes(self) -> List[Union[Table, Condition]]:
        """Get all ir_nodes in this pipelet group"""
        paths_between = nx.all_simple_paths(self.irgraph_pipe, source=self.root, target=self.sink)
        # :-1 to remove sink
        nodes_between_set = {node for path in paths_between for node in path[:-1]}
        return list(nodes_between_set)

    @property
    def size(self) -> int:
        return sum([p.length for p in self.pipelets])

    @property
    def desc(self) -> Tuple[TableName, TableName, int, List[Tuple[TableName, int]]]:
        """Description of this PipeletGroup, used for testing"""
        desc_pipelets: List[Tuple[TableName, int]] = []
        for p in self.pipelets:
            desc_pipelets.append(p.desc)
        return (self.root.name, self.sink.name, self.size, desc_pipelets)

    def __str__(self) -> str:
        pipelet_str = "\n".join(str(p) for p in self.pipelets)
        return (
            f"-------------------------------- PipeletGroupOption --------------------------------\n"
            f"root_node_name: {self.root.name}\n"
            f"sink_node_name: {self.sink.name}\n"
            f"num_pipelets: {len(self.pipelets)} {[p.root.name for p in self.pipelets]}\n"
            f"group_size: {self.size}"
            # f"{pipelet_str}"
        )
