"""
Implements a single pipeline within a target
"""
from __future__ import annotations
import math
from commons.constants import DeviceTargetType
import networkx as nx
import numpy as np

# from scipy import interpolate
from copy import deepcopy
from typing import Dict, List, Tuple, Optional, Iterator, Union, Any, TYPE_CHECKING

from commons.base_logging import logger
from commons.metric import MetricParams
from ir.ir_node import Root, Sink
from ir.general_table import GeneralTable
from ir.condition import Condition
from commons.constants import DeviceTargetType

from commons.types import IrNodeName, Probability, NanoSec, LatencyPdf, Bytes, CoreCyclesPdf, TargetLoadPdf
from ir.table import Table
from targets.target_base import MultiTargetBase, TargetBase
import commons.yaml_config as YamlConfig
import commons.config as Config

if TYPE_CHECKING:
    from ir.irgraph import IrGraph

IrNode = Union[GeneralTable, Condition]

if TYPE_CHECKING:
    from ir.irgraph import IrGraph


class IrGraphPipe(nx.DiGraph):
    """
    Implements a single pipeline, assinged to a specific target.
    """

    def __init__(self, ancor_point, target: Optional[MultiTargetBase] = None):
        super().__init__()
        self._ancor_point = ancor_point
        self._target = target
        self._root = Root()
        self._sink = Sink()
        self._ir_graph = None
        self._eval_metric: Optional[MetricParams] = None

    @property
    def sink(self) -> Sink:
        return self._sink

    @property
    def root(self) -> Root:
        return self._root

    @property
    def eval_metric(self) -> Optional[MetricParams]:
        return self._eval_metric

    @eval_metric.setter
    def eval_metric(self, metric: MetricParams):
        self._eval_metric = metric

    @property
    def normal_nodes(self) -> List[IrNode]:
        nodes = [node for node in self.nodes if node not in [self.root, self.sink]]
        return nodes

    @property
    def normal_edges(self):
        edges = [edge for edge in self.edges if self.sink not in edge and self.root not in edge]
        return edges

    @property
    def name_to_normal_node(self) -> Dict[IrNodeName, IrNode]:
        node_dict = {node.name: node for node in self.nodes if node not in [self.root, self.sink]}
        return node_dict

    @property
    def target(self):
        return self._target

    @target.setter
    def target(self, target: MultiTargetBase):
        self._target = target

    @property
    def tables(self) -> Iterator[GeneralTable]:
        for t in filter(lambda node: isinstance(node, GeneralTable), self.normal_nodes):
            yield t

    @property
    def conditions(self) -> Iterator[Condition]:
        for t in filter(lambda node: isinstance(node, Condition), self.normal_nodes):
            yield t

    @property
    def ancor_point(self) -> str:
        return self._ancor_point

    @ancor_point.setter
    def ancor_point(self, ancor_point: str):
        self._ancor_point = ancor_point

    @property
    def name(self):
        return self.ancor_point

    @property
    def ir_graph(self) -> IrGraph:
        assert self._ir_graph is not None
        return self._ir_graph

    @ir_graph.setter
    def ir_graph(self, ir_graph: IrGraph):
        self._ir_graph = ir_graph

    def refresh_edges(self):
        succs = list(self.successors(self.root))
        assert len(succs) == 1, "Root should only have one successor"
        init_node = succs[0]
        self.remove_edges_from(list(self.edges))
        node_dict = self.name_to_normal_node
        for node in node_dict.values():
            for son_name, probability in node.get_sons().items():
                if son_name is None:
                    son = self.sink
                else:
                    son = node_dict[son_name]
                self.add_edge(node, son, probability=probability)
        self.add_edge(self.root, init_node, probability=1)

    def change_next_node_in_pipelet(self, node: IrNode, new_next: IrNode, orig_next: IrNode = None) -> None:
        """Assuming the node is in a straightline pipelet, change the next node
        of node to new_next and update all necessary metadata for the nodes,
        including:
            - action_to_next_table for Table node
            - false_next, true_next for Condition node
        Args:
            orig_next:
                If orig_next is None, we automatically find the original next
                based on node's successor. In this case node should only have one single
                successor. Should be used for any nodes other than the pipelet_pred If
                orig_next is given, we use it as the original next to change the edge. In this
                case, node can have multiple successors. Should be used for pipelet_pred.
        """

        if orig_next is None:
            succs = list(self.successors(node))
            assert len(succs) == 1, f"Should only have one single next, but we got {succs} for node {node.name}"
            orig_next = succs[0]
        if orig_next == new_next:
            return
        if node == self.root:
            self.remove_edge(node, orig_next)
            self.add_edge(node, new_next, probability=1)
            return

        if isinstance(node, GeneralTable):
            orig_next_name = None if (orig_next is self.sink) else orig_next.name
            new_next_name = None if (new_next is self.sink) else new_next.name
            node.replace_next_table(orig_next_name, new_next_name)
            # assert len(node.action_to_next_table)>0 , (
            #     f"No action is found in action to next table mapping: "
            #     f"{node.action_to_next_table}"
            # )

            # for action, (next_table, prob) in node.action_to_next_table.items():
            #     assert (
            #         (next_table is None) and orig_next == self.sink
            #         or next_table == orig_next.name
            #     ), "Should only have one single next and it should be orig_next"
            #     new_next_name = None if (new_next is self.sink) else new_next.name
            #     node.action_to_next_table[action] = (new_next_name, prob)
        elif isinstance(node, Condition):
            if node.false_next == orig_next.name:
                node.false_next = new_next.name
            else:
                node.true_next = new_next.name
        else:
            raise Exception("node in change_next_node_in_pipelet can only be Table or Condition")

        self.remove_edge(node, orig_next)
        self.add_edge(node, new_next, probability=1)

    @classmethod
    def _p4cjson2ir(cls, p4cjson: Dict[str, Any], pipe_name: str, ir_graph) -> "IrGraphPipe":
        """
        generates irGraphPipe from p4c ir json
        """
        pipe_json = None
        for p in p4cjson["pipelines"]:
            if p["name"] == pipe_name:
                pipe_json = p
                break
        if not pipe_json:
            raise NameError(f"Pipeline {pipe_name} was not found in p4c json output.")

        irpipe = IrGraphPipe(ancor_point=pipe_json["name"], target=None)
        node_dict: Dict[IrNodeName, IrNode] = {}

        for json_table in pipe_json["tables"]:
            if "__HIT__" in json_table["next_tables"] or "__MISS__" in json_table["next_tables"]:
                raise NotImplementedError(
                    f"Tables with __HIT__ and __MISS__ are not supported yet because of the "
                    f"Dict[NextTableName, Probability] issue. See more details in issue #6."
                )
            irtable = Table._p4cjson2ir(table_dict=json_table, ir_graph=ir_graph)
            assert irtable.name not in node_dict, f"duplicated condition: {irtable.name}, {node_dict[irtable.name]}"
            node_dict[irtable.name] = irtable
        for json_table in pipe_json["conditionals"]:
            ircondition = Condition._p4cjson2ir(condition_dict=json_table, ir_graph=ir_graph)
            assert (
                ircondition.name not in node_dict
            ), f"duplicated condition: {ircondition.name}, {node_dict[ircondition.name]}"
            node_dict[ircondition.name] = ircondition
        for node in node_dict.values():
            for son_name, probability in node.get_sons().items():
                if son_name is None:
                    son = irpipe.sink
                else:
                    son = node_dict[son_name]
                irpipe.add_edge(node, son, probability=probability)
        if pipe_json["init_table"] is not None:
            irpipe.add_edge(irpipe.root, node_dict[pipe_json["init_table"]], probability=1)
        else:
            irpipe.add_edge(irpipe.root, irpipe.sink, probability=1)

        irpipe.ir_graph = ir_graph
        irpipe.validate()
        return irpipe

    def get_init_table(self) -> Optional[GeneralTable]:
        """
        returns the first table in the pipeline
        """
        # TODO - add sanitiy checks: single source
        succs = list(self.successors(self.root))
        if len(succs) == 0:
            return None
        elif len(succs) == 1:
            return succs[0]
        else:
            raise Exception("Multiple init_table")

    def _p4cir2json(self, unique_id: int) -> Dict[str, Any]:
        """
        export pipeline in p4c json ir format
        """
        table_list = []
        condition_list = []
        for node in self.normal_nodes:
            if isinstance(node, GeneralTable):
                table_list.append(node._p4cir2json())
            elif isinstance(node, Condition):
                condition_list.append(node._p4cir2json())
            else:
                raise TypeError("expecting only Tables/Conditions, fund: {node}")
        init_table = self.get_init_table()
        if isinstance(init_table, Sink):
            init_table_name = None
        else:
            assert init_table != None, f"Init table is none"
            init_table_name = init_table.name

        pipe_dict = {
            "name": self.ancor_point,
            "id": unique_id,
            "source_info": {},
            "init_table": init_table_name,
            "tables": table_list,
            "action_profiles": [],
            "conditionals": condition_list,
        }
        return pipe_dict

    def get_sources(self) -> List[object]:
        """return pipe sources"""
        return [node for node, in_degree in self.in_degree() if in_degree == 0 and node not in [self.root, self.sink]]

    def _validate_reachability(self):
        """checks if all nodes are reachable from the source node"""
        source = self.root
        reachable = nx.descendants(self, source)
        reachable.add(source)

        if len(reachable) != len(self):
            reachable_names = {n.name for n in reachable if n not in [self.root, self.sink]}
            all_names = {n.name for n in self.normal_nodes}
            non_reachable_names = all_names - reachable_names
            special_nodes = self.nodes - self.normal_nodes
            reachable_special_nodes = reachable - set(self.normal_nodes)
            non_reachable_special_nodes = special_nodes - reachable_special_nodes
            if len(non_reachable_special_nodes) == 1 and list(non_reachable_special_nodes)[0] == self.sink:
                return
            raise AssertionError(
                f"some nodes in {self.ancor_point} are not reachable: {non_reachable_names}"
            )  # TODO find which

    def _validate_single_source(self):
        """checks if a graph has single source"""
        sources = self.get_sources()
        if len(sources) > 1:
            source_names = ",".join([s.name for s in sources])
            raise AssertionError(
                f"in pipeline: {self.ancor_point} - more then one pipeline source:\nsources: {source_names}"
            )

    def validate(self):
        """preforms checks and verification on the ir pipeline"""
        if len(self) == 0:
            return
        self._validate_single_source()
        self._validate_reachability()

    def line_rate_latency_pdf_calibration(self, latency_pdf):
        """If the latency is less than the line rate latency, set it to the line rate latency"""
        # For the pipelet benchmark experiments, we do not need the base and line rate threshold
        if Config.DISABLE_BASE_LATENCY:
            logger.warning("DISABLE_BASE_LATENCY is set. Make sure this is running for pipelet benchmark")
            return latency_pdf

        new_latency_pdf = []
        for k, v in latency_pdf:
            k += YamlConfig.HW_LAT_MATCH_BASE + YamlConfig.HW_LAT_ACTION_BASE
            k = max(k, YamlConfig.HW_LINERATE_LATENCY)
            new_latency_pdf.append((k, v))
        return new_latency_pdf

    def eval(self) -> MetricParams:
        """current model:
        predict latency from each target, with probabilities add mitigation time
        inter packet gap: divide latency by parrallel core number
        """
        assert isinstance(self.target, MultiTargetBase), f"Cannot evalute graph before assigning targets"
        table_meas = {}
        for n in self.nodes:
            n.latency_eval = None

        roots = [n for n, d in self.in_degree() if d == 0]
        assert len(roots) == 1, f"The current graph has more than one root {[r.name for r in roots]}"
        root_table = next(nx.topological_sort(self))
        latency_pdf, per_target_load = self._recursive_latency_eval(root_table)

        if Config.USE_CALIBRATED_COST_MODEL:
            # TODO: remove migration latency from latency_pdf
            latency_pdf = self.line_rate_latency_pdf_calibration(latency_pdf)
            hw_load = per_target_load[DeviceTargetType.HW_STEERING]
            hw_load = self.line_rate_latency_pdf_calibration(hw_load)
            per_target_load[DeviceTargetType.HW_STEERING] = hw_load

        # TODO take into account insertion overhead on sw.
        lat_median, lat_p99, lat_average = self._get_latency_stats(latency_pdf)

        # TODO - add inter packet gap
        inter_packet_gap = 0
        for target_name, load_list in per_target_load.items():
            target = self.target.subtargets[target_name]
            inter_packet_gap = max(inter_packet_gap, target.get_inter_packet_gap(load_list))

        memory_used: Bytes = 0
        insertion_rate: int = 0
        for table in self.tables:
            target = self.target.subtargets[table.target_type]
            memory_used += target.get_memory_footprint(table)
            # TODO: Jiarong: Do we care about entry insertion in SW?
            assert table.entry_insertion_rate is not None, f"Entry insertion rate of table {table.name} is not set"
            insertion_rate += table.entry_insertion_rate
        memory_size: Bytes = 32e9  # TODO, get from target.
        insertion_latency: NanoSec = 10

        measurments = MetricParams(
            p99_latency=lat_p99,  # TODO
            median_latency=lat_median,
            average_latency=lat_average,
            inter_packet_gap=inter_packet_gap,
            entry_insertion_latency=insertion_latency,
            entry_insertion_rate=insertion_rate,
            compute_utilization=0,
            energy_per_packet=0,  # TODO can calc from the lookups per target
            memory_used=memory_used,
            memory_utilization=memory_used / memory_size,  # TODO seperate between targets / shared mem?
        )
        return measurments

    @classmethod
    def _stats_interpolate(cls, x, y):
        """Interpolate the stats for more accurate comparision

        x: an array for x values
        y: an array for corresponding y values
        """
        assert len(x) == len(y), f"The length of x and y should be same."
        # The latency is deterministic, we add x=x[0](latency) and y=0(prob)
        if len(x) == 1:
            assert math.isclose(y[0], 1), f"When the x has one value, y must be 1"
            x.insert(0, 0)
            y.insert(0, 0)
        # Disable this, because it makes pypy very slow
        return x, y

        # f=interpolate.interp1d(x, y, kind='linear')
        step = max(int((x[-1] - x[0]) / 1000), 1)
        new_x = list(range(x[0], x[-1] + 1, step))
        if len(new_x) <= len(x):
            new_x = x
        # new_y = [float(f(i)) for i in new_x]
        new_y = [float(np.interp(i, x, y)) for i in new_x]
        return new_x, new_y

    def _get_latency_stats(self, latency_list: LatencyPdf) -> Tuple[NanoSec, NanoSec, NanoSec]:
        """
        returns p50 and p99 of a given latency list
        """
        unified_prob = []
        unified_lat = []
        average_latency: NanoSec = 0
        for t, p in latency_list:
            unified_prob.append(p)
            unified_lat.append(t)
            average_latency += t * p
        if len(unified_lat) == 0:
            return 0, 0, 0
        # sort both list accordig to latency
        unified_lat, unified_prob = zip(*sorted(zip(unified_lat, unified_prob)))

        lat_cdf = np.cumsum(unified_prob)

        new_unified_lat, new_lat_cdf = IrGraphPipe._stats_interpolate(list(unified_lat), list(lat_cdf))

        # get first index of CDF greater than 0.99
        arg_p99 = np.argwhere(np.array(new_lat_cdf) >= 0.99)
        # sometimes, there is no prob larger than p99, we have to use the closest value
        arg_p99_idx = -1 if len(arg_p99) == 0 else arg_p99[0][0]
        p99_lat = new_unified_lat[arg_p99_idx]
        p50_lat = new_unified_lat[np.argwhere(np.array(new_lat_cdf) >= 0.5)[0][0]]
        # logger.debug('p99_lat: %f, p50_lat: %f.', p99_lat, p50_lat)
        # p99_lat = unified_lat[np.argwhere(lat_cdf>0.99)[0][0]]
        # p50_lat = unified_lat[np.argwhere(lat_cdf>0.5)[0][0]]
        return p50_lat, p99_lat, average_latency

    def _convolve_meas_join(
        self, latency_list1: List[Tuple[LatencyPdf, Probability]], latency_list2: LatencyPdf
    ) -> LatencyPdf:
        """
        merges two multi-target estimations one following another.
        -> convovlve latencies
        """
        # TODO - improve perf.
        joint_dict = {}
        cdf = 0
        for next_pdf, next_prob in latency_list1:
            for t1, p1 in next_pdf:
                for (t2, p2) in latency_list2:
                    pdf = next_prob * p1 * p2
                    cdf += pdf
                    joint_dict[t1 + t2] = joint_dict.get(t1 + t2, 0) + pdf
        assert math.isclose(cdf, 1), f"cdf = {cdf}, prob_list = {latency_list1},{latency_list2}"
        return [(k, v) for k, v in joint_dict.items()]

    # TODO - no so sure if needed - maybe just use the recursive eval
    # def _latency_meas_choose(self,branch_list: List[Tuple[TargetLatencyPdf,Probability]],previous_target:TargetBase) -> TargetLatencyPdf:
    #     """
    #     merges two multi-target estimations one OR the another.
    #     -> rescale and add latencies
    #     """
    #     result = {target:{} for target in self.target.subtarget_names}
    #     for target_latency_list, branch_prob in branch_list:
    #         for target in self.target.subtarget_names:
    #             mitigation_lat = self.target.get_mitigation_latency(previous_target,target)
    #             for (t1,p1) in target_latency_list[target]:
    #                 prob = result[target].get(t1,0) + p1*branch_prob
    #                 assert(1>=prob>=0)
    #                 result[target][t1+mitigation_lat] = prob

    #     result_target_lat_list = {}
    #     for target in self.target.subtarget_names:
    #         result_target_lat_list[target] = [(t,p) for t,p in result[target].items()] # TODO keep ordering? remain with dict?
    #     return result_target_lat_list

    def _recursive_latency_eval(
        self, table: IrNode, stop_table: Optional[IrNode] = None  # for pipelet evaluation
    ) -> Tuple[LatencyPdf, TargetLoadPdf]:
        """
        start from root and reverse dfs latency estimation.
        TODO - collect load per target as well.
        TODO - add lru cache for performance.
        """
        if isinstance(table, GeneralTable):
            pass
            # logger.debug(f"In _recursive_latency_eval, table {table.name}")
            # logger.debug(f"Next tables: {table._next_table_selector.next_tables}")
        assert self.target != None, f"IgraphPipe must be assigned with a target before evaluation"

        if table.latency_eval != None:
            return deepcopy(table.latency_eval)
        if isinstance(table, Sink):
            tpdf = {target: [(0, 1)] for target in self.target.subtarget_types}
            return ([(0, 1)], tpdf)
        elif isinstance(table, Root):
            is_root = True
        else:
            is_root = False
            curr_target_type = table.target_type
            assert curr_target_type != DeviceTargetType.UNASSIGNED, f"table {table.name} was not assigned to a target"

        next_meas_list = []
        next_per_target_load_list = []
        total_prob = 0
        for next_table in self.successors(table):
            if stop_table != None and table.name == stop_table.name:
                break
            go_to_probability = self.get_edge_data(table, next_table).get("probability", 0)
            if math.isclose(go_to_probability, 0):
                continue
            total_prob += go_to_probability
            next_meas, per_target_load = self._recursive_latency_eval(next_table, stop_table)
            if not (is_root or isinstance(next_table, Sink)):
                next_target_type = next_table.target_type
                migration_lat = self.target.get_mitigation_latency(curr_target_type, next_target_type)
                if migration_lat > 0:
                    mitigation_lat = migration_lat
                    next_meas = [(t + mitigation_lat, p) for t, p in next_meas]
            next_meas_list.append((next_meas, go_to_probability))
            next_per_target_load_list.append((per_target_load, go_to_probability))

        if total_prob < 1:
            # can happen if action is drop
            next_meas_list.append(([(0, 1)], 1 - total_prob))
            d = {t: [(0, 1)] for t in self.target.subtarget_types}
            next_per_target_load_list.append((d, 1 - total_prob))

        if is_root:
            curr_table_lat = [(0, 1)]
        else:
            curr_table_lat = self.target.latency_eval(table)
            # logger.debug(f"Current table: {table.name}, latency: {curr_table_lat}")
            # logger.debug(f"next_tables: {table.next_tables}")
            # logger.debug(f"action_probabilities: {table.action_to_probability}")
            # logger.debug(f"next_table_to_probability: {table.get_sons()}")
        comulative_latency = self._convolve_meas_join(next_meas_list, curr_table_lat)

        curr_table_load = curr_table_lat  # TODO implement: self.target.load_eval(table)
        # all next options are weighted, and this table load is convolved with the next options of the relevant target.
        comulative_per_target_load = {}
        for target_type in self.target.subtarget_types:
            target_load_list: CoreCyclesPdf = []
            for per_target_load_dict, branch_prob in next_per_target_load_list:
                target_load_list += [(l, p * branch_prob) for (l, p) in per_target_load_dict[target_type]]

            if (not is_root) and (target_type == table.target_type):
                comulative_per_target_load[target_type] = self._convolve_meas_join(
                    [(target_load_list, 1)], curr_table_load
                )
            else:
                comulative_per_target_load[target_type] = target_load_list
        table.latency_eval = comulative_latency, comulative_per_target_load
        return comulative_latency, comulative_per_target_load
