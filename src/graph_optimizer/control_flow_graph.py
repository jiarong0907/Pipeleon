import os
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
import networkx as nx
import matplotlib.pyplot as plt
import copy

from commons.constants import (
    CFGNodeType,
    BranchCheckResult,
)
from commons.types import IrNodeName
from commons.base_logging import logger
from ir.condition import Condition
from ir.ir_node import Root
from ir.irgraph_pipe import IrGraphPipe, IrNode, Sink
from ir.table import Table
from graph_optimizer.pipelet import Pipelet, PipeletGroup


@dataclass
class CFGnode:
    depth: int
    ir_nodes: List[Union[IrNode, Root, Sink]]
    node_type: CFGNodeType = CFGNodeType.UNDEFINED
    aggregation: Optional["CFGnode"] = None
    condition: Optional["CFGnode"] = None
    is_mini_topk_component: bool = False

    def __repr__(self):
        """For networkx node label"""
        return self.ir_nodes[0].name

    def __hash__(self) -> int:
        # return hash((self.depth, self.node_type, hash(frozenset(self.ir_nodes))))
        return hash((self.node_type, hash(frozenset(self.ir_nodes))))

    def __eq__(self, other):
        if (
            type(other) == type(self)
            and other.depth == self.depth
            and other.ir_nodes == self.ir_nodes
            and other.node_type == self.node_type
        ):
            return True
        else:
            return False


class ControlFlowGraph(nx.DiGraph):
    def __init__(self):
        super().__init__()
        self._root = None
        self._sink = None

    # Refer to: https://stackoverflow.com/questions/46283738/attributeerror-when-using-python-deepcopy
    # __new__ instead of __init__ to establish necessary attributes invariant
    # You could use both __new__ and __init__, but that's usually more complicated
    # than you really need
    # def __new__(cls):
    #     self = super().__new__(cls)  # Must explicitly create the new object
    #     # Aside from explicit construction and return, rest of __new__ is same as __init__
    #     self._root = None
    #     self._sink = None
    #     # __new__ returns the new object
    #     return self

    # def __getnewargs__(self):
    #     # Return the arguments that *must* be passed to __new__
    #     return (self._irgraph_pipe,)

    # def __deepcopy__(self, memo):
    #     # Deepcopy only the id attribute, then construct the new instance and map
    #     # the id() of the existing copy to the new instance in the memo dictionary
    #     memo[id(self)] = newself = self.__class__()
    #     # Now that memo is populated with a hashable instance, copy the other attributes:
    #     newself._root = copy.deepcopy(self._root, memo)
    #     newself._sink = copy.deepcopy(self._sink, memo)
    #     return newself

    @property
    def root(self) -> CFGnode:
        assert self._root is not None, f"root was not set."
        return self._root

    @root.setter
    def root(self, root: CFGnode):
        self._root = root

    @property
    def sink(self) -> CFGnode:
        assert self._sink is not None, f"sink was not set."
        return self._sink

    @sink.setter
    def sink(self, sink: CFGnode):
        self._sink = sink

    @classmethod
    def _get_cfg_node_type(cls, irgraph_pipe: IrGraphPipe, ir_node: Union[IrNode, Root, Sink]) -> CFGNodeType:
        """ir node type to cfg node type"""
        if isinstance(ir_node, Table):
            if len(set(ir_node.next_tables.values())) == 1:
                return CFGNodeType.TABLE
            else:
                return CFGNodeType.SWITCH
        elif isinstance(ir_node, Condition):
            return CFGNodeType.IF
        elif isinstance(ir_node, Root):
            return CFGNodeType.ROOT
        elif isinstance(ir_node, Sink):
            return CFGNodeType.SINK
        else:
            raise ValueError(f"Unexpected ir node type {type(ir_node)}.")

    @classmethod
    def _handle_if(
        cls,
        irgraph_pipe: IrGraphPipe,
        cfg_graph: "ControlFlowGraph",
        cfg_node: CFGnode,
        ir_node_to_cfg_node: Dict[IrNodeName, CFGnode],
    ):
        assert len(cfg_node.ir_nodes) == 1 and isinstance(
            cfg_node.ir_nodes[0], Condition
        ), f"if branch cfg node should have only one ir node which is the if branch itself"
        successors = list(irgraph_pipe.successors(cfg_node.ir_nodes[0]))
        assert len(successors) == 2, f"conditional node should have two successors"
        for succ in successors:
            res = cls._get_next_cfg_node(cfg_graph, irgraph_pipe, cfg_node, succ, ir_node_to_cfg_node)
            branch_node = res[1]
            cfg_graph.add_edge(cfg_node, branch_node)
            if not res[0]:
                ir_node_to_cfg_node[succ.name] = branch_node

    @classmethod
    def _handle_switch(
        cls,
        irgraph_pipe: IrGraphPipe,
        cfg_graph: "ControlFlowGraph",
        cfg_node: CFGnode,
        ir_node_to_cfg_node: Dict[IrNodeName, CFGnode],
    ):
        assert len(cfg_node.ir_nodes) == 1 and isinstance(
            cfg_node.ir_nodes[0], Table
        ), f"Switch should have only one ir node which is the switch table itself."
        successors = list(irgraph_pipe.successors(cfg_node.ir_nodes[0]))
        assert len(successors) >= 1, f"Switch table should have more tha one successors"
        for succ in successors:
            res = cls._get_next_cfg_node(cfg_graph, irgraph_pipe, cfg_node, succ, ir_node_to_cfg_node)
            branch_node = res[1]
            cfg_graph.add_edge(cfg_node, branch_node)
            if not res[0]:
                ir_node_to_cfg_node[succ.name] = branch_node

    @classmethod
    def _handle_table(
        cls,
        irgraph_pipe: IrGraphPipe,
        cfg_graph: "ControlFlowGraph",
        cfg_node: CFGnode,
        ir_node_to_cfg_node: Dict[IrNodeName, CFGnode],
    ):
        assert isinstance(
            cfg_node.ir_nodes[-1], Table
        ), f"The last ir node of a straight line program should be Table. But this is {cfg_node.ir_nodes[-1].name}"
        successors = list(irgraph_pipe.successors(cfg_node.ir_nodes[-1]))
        assert (
            len(successors) == 1
        ), f"Table should have only one successor. {cfg_node.ir_nodes[-1].name, cfg_node.ir_nodes[-1].next_tables.values()}"

        res = cls._get_next_cfg_node(cfg_graph, irgraph_pipe, cfg_node, successors[0], ir_node_to_cfg_node)
        next_node = res[1]

        cfg_graph.add_edge(cfg_node, next_node)
        if not res[0]:
            ir_node_to_cfg_node[successors[0].name] = next_node

    @classmethod
    def _get_next_cfg_node(
        cls,
        cfg: "ControlFlowGraph",
        irgraph_pipe: IrGraphPipe,
        cur_cfg_node: CFGnode,
        first_next_ir_node: IrNode,
        ir_cfg_nodes: Dict[IrNodeName, CFGnode],
    ):
        """Create the next cfg node for the current cfg node

        Parameters:
            - first_next_ir_node: The first ir node of the next cfg node
        """
        depth = cur_cfg_node.depth + 1
        cfg_node = ir_cfg_nodes.get(first_next_ir_node.name, None)
        # cfg node exists
        if cfg_node:
            cfg_node.depth = max(cfg_node.depth, depth)
            return [True, cfg_node]

        # node not exists
        cfg_node = CFGnode(depth, [first_next_ir_node])
        node_type = cls._get_cfg_node_type(irgraph_pipe, first_next_ir_node)
        if node_type == CFGNodeType.IF or node_type == CFGNodeType.SWITCH:
            cfg_node.node_type = node_type
        elif node_type == CFGNodeType.TABLE:
            cfg_node.node_type = node_type
            current_ir_node = cfg_node.ir_nodes[0]
            while True:
                if not isinstance(current_ir_node, Table):
                    break
                successors = list(irgraph_pipe.successors(current_ir_node))
                if (
                    len(successors) == 1
                    and isinstance(successors[0], Table)
                    and len(set(successors[0].next_tables.values())) == 1
                ):
                    current_ir_node = successors[0]
                    predecessors = list(irgraph_pipe.predecessors(current_ir_node))
                    if len(predecessors) > 1:
                        break
                    cfg_node.ir_nodes.append(current_ir_node)
                else:
                    break

        elif node_type == CFGNodeType.ROOT:
            raise Exception(f"Root should have been consumed before entering this function.")
        elif node_type == CFGNodeType.SINK:
            # raise Exception(f"Sink should have been consumed before entering this branch.")
            cfg_node.node_type = node_type
        else:
            raise ValueError(f"Unexpected node type {node_type}")

        # ir_cfg_nodes[first_next_ir_node.name] = cfg_node
        return [False, cfg_node]

    def _get_reserve_cfg_graph(self) -> "ControlFlowGraph":
        return self.reverse(copy=True)

    @classmethod
    def _build_cfg(cls, irgraph_pipe: IrGraphPipe) -> "ControlFlowGraph":
        cfg_graph = ControlFlowGraph()

        ir_root = irgraph_pipe.root
        ir_sink = irgraph_pipe.sink
        cfg_root = CFGnode(depth=0, ir_nodes=[ir_root], node_type=CFGNodeType.ROOT)
        cfg_sink = None
        # cfg_sink = CFGnode(depth=1, ir_nodes=[ir_sink], node_type=CFGNodeType.SINK)
        # one ir node may be a child node of multiple nodes
        # use this to record whether current ir node has a corresponding cfg node
        ir_node_to_cfg_node: Dict[IrNodeName, CFGnode] = {ir_root.name: cfg_root}

        depth = 0
        bfs_queue: List[CFGnode] = [cfg_root]
        while bfs_queue:
            cfg_node = bfs_queue.pop(0)
            if cfg_node.node_type == CFGNodeType.ROOT:
                successors = list(irgraph_pipe.successors(cfg_node.ir_nodes[0]))
                assert len(successors) == 1, f"Root should have only one successor"

                res = cls._get_next_cfg_node(cfg_graph, irgraph_pipe, cfg_node, successors[0], ir_node_to_cfg_node)
                next_node = res[1]
                cfg_graph.add_edge(cfg_node, next_node)
                if not res[0]:
                    ir_node_to_cfg_node[successors[0].name] = next_node
                # next_cfg_node = CFGnode(depth=depth + 1, ir_nodes=[successors[0]])
                # next_cfg_node.node_type = ControlFlowGraph._get_cfg_node_type(irgraph_pipe, successors[0])
                # cfg_graph.add_edge(cfg_root, next_cfg_node)

                # if next_cfg_node.node_type == CFGNodeType.SINK:
                #     # There could be multiple appearance of SINK
                #     # We just ignore it and return the cfg at the end
                #     cfg_sink = next_cfg_node
                #     continue
                # elif next_cfg_node.node_type == CFGNodeType.IF:
                #     cls._handle_if(irgraph_pipe, cfg_graph, next_cfg_node, ir_node_to_cfg_node)
                # elif next_cfg_node.node_type == CFGNodeType.SWITCH:
                #     cls._handle_switch(irgraph_pipe, cfg_graph, next_cfg_node, ir_node_to_cfg_node)
                # elif next_cfg_node.node_type == CFGNodeType.TABLE:
                #     cls._handle_table(irgraph_pipe, cfg_graph, next_cfg_node, ir_node_to_cfg_node)
                # else:
                #     raise ValueError(f"Unexpected CFGNode type {next_cfg_node.node_type}.")

            elif cfg_node.node_type == CFGNodeType.SINK:
                # There could be multiple appearance of SINK
                # We just ignore it and return the cfg at the end
                cfg_sink = cfg_node
                # if set(bfs_queue) == {cfg_sink}:
                #     cfg_node.depth = max(cfg_node.depth, depth)
                #     break
                # cfg_node.depth = max(cfg_node.depth, depth)
                continue

            elif cfg_node.node_type == CFGNodeType.IF:
                cls._handle_if(irgraph_pipe, cfg_graph, cfg_node, ir_node_to_cfg_node)

            elif cfg_node.node_type == CFGNodeType.SWITCH:
                cls._handle_switch(irgraph_pipe, cfg_graph, cfg_node, ir_node_to_cfg_node)

            elif cfg_node.node_type == CFGNodeType.TABLE:
                cls._handle_table(irgraph_pipe, cfg_graph, cfg_node, ir_node_to_cfg_node)

            else:
                raise ValueError(f"Unexpected CFGNode type {cfg_node.node_type}.")

            depth += 1
            for child in list(cfg_graph.successors(cfg_node)):
                bfs_queue.append(child)

        assert cfg_sink is not None, f"Sink is not reached"
        cfg_graph.root = cfg_root
        cfg_graph.sink = cfg_sink
        return cfg_graph

    @classmethod
    def _draw_cfg(cls, cfg: "ControlFlowGraph", figure_name: str):
        pos = nx.spring_layout(cfg)
        nx.draw(cfg, pos, node_size=1000, width=2.0, with_labels=True)
        plt.draw()
        save_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), figure_name)
        plt.savefig(save_path)

    # @classmethod
    # def _compare_copied_ir_nodes(cls, copied_node: CFGnode, node: CFGnode):
    #     copied_ir_nodes = set(copied_node.ir_nodes)
    #     ir_nodes = set(node.ir_nodes)
    #     if copied_ir_nodes == ir_nodes:
    #         return True
    #     else:
    #         return False

    # @classmethod
    # def _compare_copied_node(cls, copied_node: CFGnode, node: CFGnode):

    #     if copied_node.depth != node.depth:
    #         return False
    #     elif copied_node.node_type != node.node_type:
    #         return False
    #     elif not ControlFlowGraph._compare_copied_ir_nodes:
    #         return False
    #     else:
    #         return True

    # @classmethod
    # def _get_corresponding_copied_node(cls, copied_cfg: 'ControlFlowGraph', node: CFGnode):
    #     copied_nodes = list(copied_cfg.nodes)
    #     assert len(copied_nodes) > 0, f"The copied cfg has no node"

    #     for copied_node in copied_nodes:
    #         if str(copied_node) == str(node):
    #             return copied_node
    #         # if ControlFlowGraph._compare_copied_node(copied_node, node):
    #         #     return copied_node

    #     return None

    @classmethod
    def _store_node_edges_to_delete(cls, cfg: "ControlFlowGraph", cfg_node: CFGnode):
        """store the node that will be deleted to find dominatos and its edges
        so we can add the node and its edges back to the cfg after checking
        """
        assert cfg_node in cfg, f"The node to be deleted is not in the cfg"

        # node_predecessors = list(cfg.predecessors(cfg_node))
        # predecessor_edges = []
        # if len(node_predecessors) > 0:
        #     for predecessor in node_predecessors:
        #         edge = (predecessor, cfg_node)
        #         predecessor_edges.append(edge)

        # node_successors = list(cfg.successors(cfg_node))
        # successor_edges = []
        # if len(node_successors) > 0:
        #     for successor in node_successors:
        #         edge = (cfg_node, successor)
        #         successor_edges.append(edge)

        # total_edges = predecessor_edges + successor_edges
        # assert len(total_edges) > 0, f"The node {cfg_node} to be deleted has no edges"

        # res = [predecessor_edges, successor_edges]
        res = list(cfg.edges(cfg_node))
        assert len(res) > 0, f"The node {cfg_node} to be deleted has no edges"
        return res

    @classmethod
    def _delete_node_edges(cls, cfg: "ControlFlowGraph", cfg_node: CFGnode, edges):
        """delete all edges of target node to check dominators"""
        # predecessor_edges = edges[0]
        # successor_edges = edges[1]

        # total_edges = predecessor_edges + successor_edges
        # assert len(total_edges) > 0, f"The node {cfg_node} to be deleted has no edges"

        # if len(predecessor_edges) > 0:
        #     cfg.remove_edges_from(predecessor_edges)

        # if len(successor_edges) > 0:
        #     cfg.remove_edges_from(successor_edges)

        assert len(edges) > 0, f"The node {cfg_node} to be deleted has no edges"
        for edge in edges:
            assert edge[0] in cfg, f"The node {edge[0]} of the edge is not in cfg"
            assert edge[1] in cfg, f"The node {edge[1]} of the edge is not in cfg"

        cfg.remove_edges_from(edges)

        return cfg

    @classmethod
    def _add_node_edges_back(cls, cfg: "ControlFlowGraph", root_node, cfg_node: CFGnode, edges):
        """add the deleted node and its edges back to the cfg after checking dominators"""
        # predecessor_edges = edges[0]
        # successor_edges = edges[1]

        # if len(predecessor_edges) > 0:
        #     cfg.add_edges_from(predecessor_edges)

        # if len(successor_edges) > 0:
        #     cfg.add_edges_from(successor_edges)
        cfg.add_edges_from(edges)

        assert cfg_node in cfg, f"The node is not added back to the cfg!"
        assert nx.has_path(cfg, root_node, cfg_node), f"Target node can't be reached from root or sink"
        return cfg

    @classmethod
    def _get_dominators(cls, cfg: "ControlFlowGraph", cfg_node: CFGnode, tag: bool, root_node: CFGnode):
        """get node cfg_node's dominators, node cfg_node is in the graph cfg.
        if using reserve cfg to get post dominators, tag is True, root node is Sink
        """
        assert cfg_node in cfg, f"Target node is not in the cfg graph"
        assert root_node in cfg, f"Root or sink node is not in the cfg graph"
        dominator_list = []
        d = cfg_node.depth
        # root_node = cfg.root
        assert nx.has_path(cfg, root_node, cfg_node), f"Target node can't be reached from root or sink"

        if cfg_node == root_node:
            # root's dominator is itself, sink's post dominator is also itself
            dominator_list.append(root_node)
            return dominator_list

        # elif cfg_node == sink_node:
        #     dominator_list.append(cfg_node)
        #     return dominator_list

        else:
            # get other nodes' dominators
            # root and node itself are dominators
            dominator_list.append(root_node)
            dominator_list.append(cfg_node)

            # get other dominators
            other_nodes = list(cfg.nodes)
            other_nodes.remove(root_node)
            other_nodes.remove(cfg_node)

            # other dominators are in front of the target node
            num = len(other_nodes)
            possible_nodes = []
            if tag:
                for i in range(num):
                    node = other_nodes[i]
                    if node.depth >= d:
                        possible_nodes.append(node)

                # for node in other_nodes:
                #     if node.depth < d:
                #         other_nodes.remove(node)
            else:
                for i in range(num):
                    node = other_nodes[i]
                    if node.depth <= d:
                        possible_nodes.append(node)

                # for node in other_nodes:
                #     node_depth = node.depth
                #     if node_depth > d:
                #         other_nodes.remove(node)

            for node in possible_nodes:
                assert node in cfg, f"The node to be deleted is in the cfg"
                node_edges = ControlFlowGraph._store_node_edges_to_delete(cfg, node)
                cfg = ControlFlowGraph._delete_node_edges(cfg, node, node_edges)

                if not nx.has_path(cfg, root_node, cfg_node):
                    dominator_list.append(node)

                cfg = ControlFlowGraph._add_node_edges_back(cfg, root_node, node, node_edges)

        return dominator_list

    @classmethod
    def _get_aggregation(cls, cfg: "ControlFlowGraph"):
        dominators = {}
        post_dominators = {}

        root_node = cfg.root
        sink_node = cfg.sink

        # get dominators
        all_nodes = list(cfg.nodes)
        assert len(all_nodes) > 0, f"The graph has no node"
        # all_nodes.remove(cfg.root)
        # all_nodes.remove(cfg.sink)

        dominator_list = []
        for node in all_nodes:
            dominator_list = ControlFlowGraph._get_dominators(cfg, node, False, root_node)
            dominators[node] = dominator_list

        # get post_dominators
        cfg = cfg._get_reserve_cfg_graph()
        all_nodes = list(cfg.nodes)
        assert len(all_nodes) > 0, f"The graph has no node"
        # all_nodes.remove(cfg.root)
        # all_nodes.remove(cfg.sink)

        post_dominator_list = []
        for node in all_nodes:
            post_dominator_list = ControlFlowGraph._get_dominators(cfg, node, True, sink_node)
            post_dominators[node] = post_dominator_list

        assert dominators is not None, f"Can't get dominators"
        assert post_dominators is not None, f"Can't get post_dominators"

        # get aggregation node
        cfg = cfg._get_reserve_cfg_graph()
        all_nodes = list(cfg.nodes)
        assert len(all_nodes) > 0, f"The graph has no node"
        # all_nodes.remove(cfg.root)
        # all_nodes.remove(cfg.sink)

        dominator_list = []
        post_dominator_list = []

        for node in all_nodes:
            if node.node_type == CFGNodeType.IF or node.node_type == CFGNodeType.SWITCH:
                post_dominator_list = post_dominators[node]
                assert len(post_dominator_list) > 0, f"Current condition node has no post dominators"
                post_dominator_list.remove(node)  # don't need to consider the node itself
                assert len(post_dominator_list) > 0, f"Current condition node only has itself as a post dominator"

                possible_aggregations = []
                for post_dom in post_dominator_list:
                    dominator_list = dominators[post_dom]
                    assert len(dominator_list) > 0, f"Current node has no dominators"
                    if node in dominator_list:
                        possible_aggregations.append(post_dom)

                num = len(possible_aggregations)
                # assert num > 0, f"Can't find possible aggregations of {node}"
                if num == 1:
                    node.aggregation = possible_aggregations[0]
                    possible_aggregations[0].condition = node
                elif num == 0:
                    continue
                else:
                    closest_node = possible_aggregations[0]
                    for i in range(1, num):
                        if possible_aggregations[i].depth < closest_node.depth:
                            closest_node = possible_aggregations[i]
                    node.aggregation = closest_node
                    # if the node is a common aggregation for multiple branches, only record the first branch
                    if closest_node.condition == None:
                        closest_node.condition = node

        # for node in all_nodes:
        #     dominator_list = dominators[node]
        #     assert len(dominator_list) > 0, f"Current node has no dominators"
        #     dominator_list.remove(node)   # don't need to consider the node itself

        #     if len(dominator_list) > 0:
        #         for dom in dominator_list:
        #             if (dom.node_type == CFGNodeType.IF or
        #                 dom.node_type == CFGNodeType.SWITCH
        #                 # only if or switch needs aggregation node
        #                 ):
        #                 post_dominator_list = post_dominators[dom]
        #                 assert len(post_dominator_list) > 0, f"Current node has no postdominators"

        #                 if node in post_dominator_list:
        #                     dom.aggregation = node

    # third part
    @classmethod
    def _get_topk_pipelet_roots(cls, topk_pipelet: List[Pipelet]):
        assert len(topk_pipelet) > 0, f"There is no topk pipelet"
        topk_pipelet_roots = []
        topk_pipelet_dict = {}

        for pipelet in topk_pipelet:
            topk_pipelet_roots.append(pipelet.root)
            topk_pipelet_dict[pipelet.root] = pipelet

        res = [topk_pipelet_roots, topk_pipelet_dict]
        return res

    @classmethod
    def _check_tab_node(
        cls,
        cfg_node: CFGnode,
        cfg_graph: "ControlFlowGraph",
        irgraph_pipe: IrGraphPipe,
        topk_pipelet_groups: List[PipeletGroup],
        topk_pipelet_roots: List[Table],
        topk_pipelet_dict: Dict[Table, Pipelet],
    ) -> List[PipeletGroup]:

        assert len(cfg_node.ir_nodes) > 0, f"The cfg_node don't include any ir_node"

        # check if the first ir_node in the cfg_node is the same as
        # the first ir_node in the topk pipelet
        ir_node = cfg_node.ir_nodes[0]  # the first ir_node in the cfg_node

        if ir_node in topk_pipelet_roots:
            cfg_node.is_mini_topk_component = True
            corresponding_topk_pipelet = topk_pipelet_dict[ir_node]

            successors = list(cfg_graph.successors(cfg_node))
            assert len(successors) > 0, f"Table node should have one successor"
            successor = successors[0]
            pipelet_group_sink = successor.ir_nodes[0]
            corresponding_topk_pipelet_group = PipeletGroup(
                irgraph_pipe, ir_node, pipelet_group_sink, [corresponding_topk_pipelet]
            )
            topk_pipelet_groups.append(corresponding_topk_pipelet_group)

        return topk_pipelet_groups

    @classmethod
    def _get_branch_group(
        cls,
        irgraph_pipe: IrGraphPipe,
        root: Union[Table, Condition],
        sink: Union[Table, Condition, Sink],
        groups: List[PipeletGroup],
    ) -> List[PipeletGroup]:
        """After checking one condition branch, the result may be multiple lists
        We need to combine these lists and get one big list
        """
        branch_group = []
        for small_group in groups:
            branch_group.extend(small_group.pipelets)
        branch_pipelet_group = PipeletGroup(irgraph_pipe, root, sink, branch_group)
        return [branch_pipelet_group]

    @classmethod
    def _check_smaller_branch(
        cls,
        cfg_graph: "ControlFlowGraph",
        irgraph_pipe: IrGraphPipe,
        condition_node: CFGnode,
        aggregation_node: CFGnode,
        group: List[PipeletGroup],
    ):
        """Check whether the branch without the aggregation can be a smaller topk group"""
        branch_tag = BranchCheckResult.FALSE
        condition_node_successors = list(cfg_graph.successors(condition_node))
        for node in condition_node_successors:
            # if there exists an edge directly conneting both the condition node and
            # the aggregation node, the branch can't generate a smaller group
            if node == aggregation_node:
                branch_tag = BranchCheckResult.FALSE
                res = []
                res.append(branch_tag)
                res.append(group)
                return res

        edge_num = len(condition_node_successors)
        if condition_node.node_type == CFGNodeType.IF:
            if len(group) == edge_num:
                branch_tag = BranchCheckResult.SMALLER
                group_root = condition_node.ir_nodes[0]
                group_sink = aggregation_node.ir_nodes[0]
                group = ControlFlowGraph._get_branch_group(irgraph_pipe, group_root, group_sink, group)
            else:
                branch_tag = BranchCheckResult.FALSE
        elif condition_node.node_type == CFGNodeType.SWITCH:
            # if len(group) == edge_num + 1:   # in this case, switch node is also a topk pipelet
            if len(group) == edge_num:  # in this case, switch node is also a topk pipelet
                branch_tag = BranchCheckResult.SMALLER
                group_root = condition_node.ir_nodes[0]
                group_sink = aggregation_node.ir_nodes[0]
                group = ControlFlowGraph._get_branch_group(irgraph_pipe, group_root, group_sink, group)
            else:
                branch_tag = BranchCheckResult.FALSE
        res = []
        res.append(branch_tag)
        res.append(group)
        return res

    @classmethod
    def _add_subbranch_and_check_larger_branch(
        cls,
        cfg_graph: "ControlFlowGraph",
        cfg_node: CFGnode,
        pre_branch_group: List[PipeletGroup],
        group: List[PipeletGroup],
        topk_pipelet_dict: Dict[Table, Pipelet],
    ):
        """Add the topk group of subbranch into the topk group of prebranch.
        Check whether the branch with its predecessor node can be a larger topk group"""
        all_predecessors = list(cfg_graph.predecessors(cfg_node))
        branch_predecessors = []
        # one condition node may have multiple predecessors
        # some predecessors may not be in the current branch
        # we only need the predecessors in the current branch
        # TODO: cannot combine in the case of two directly consecutive conditional branches
        topk_pipelet_dict_keys = list(topk_pipelet_dict.keys())
        for predecessor in all_predecessors:
            if predecessor.ir_nodes[0] in topk_pipelet_dict_keys:
                corresponding_pipelet = topk_pipelet_dict[predecessor.ir_nodes[0]]
                for pipeletgroup in pre_branch_group:
                    if (corresponding_pipelet in pipeletgroup.pipelets) and (len(pipeletgroup.pipelets) == 1):
                        branch_predecessors.append(predecessor)

        num = len(branch_predecessors)
        if num == 1:
            # we only need the "table" predecessors
            tag = True
            predecessor = branch_predecessors[0]
            if predecessor.node_type != CFGNodeType.TABLE:
                tag = False

            if not tag:
                pre_branch_group.extend(group)
                return pre_branch_group
            else:
                # remove the list of the predecessor node from the pre_branch_group
                corresponding_pipelet = topk_pipelet_dict[predecessor.ir_nodes[0]]
                predecessor_pipeletgroup = None
                for pipeletgroup in pre_branch_group:
                    if (corresponding_pipelet in pipeletgroup.pipelets) and (len(pipeletgroup.pipelets) == 1):
                        predecessor_pipeletgroup = pipeletgroup
                        pre_branch_group.remove(pipeletgroup)
                        break
                assert (
                    predecessor_pipeletgroup
                ), f"Although the branch tag is True, we don't find the predecessor of the sub branch in the branch pipelet groups."

                # combine the list of the predecessor node with the list in current group
                predecessor_pipeletgroup.sink = group[0].sink
                predecessor_pipeletgroup.pipelets.extend(group[0].pipelets)

                # add current group into the pre_branch_group
                pre_branch_group.append(predecessor_pipeletgroup)
                return pre_branch_group
        else:  # the case of two directly consecutive conditional branches or others
            pre_branch_group.extend(group)
            return pre_branch_group

    @classmethod
    def _check_condition_branch(
        cls,
        cfg_graph: "ControlFlowGraph",
        irgraph_pipe: IrGraphPipe,
        cfg_node: CFGnode,
        topk_pipelet_roots: List[Table],
        topk_pipelet_dict: Dict[Table, Pipelet],
        same_tag: bool,
    ):
        """if the condition branch has its own aggregation node, the same_tag is false"""

        aggregation_node = cfg_node.aggregation
        assert (
            aggregation_node != None
        ), f"The condition branch should have an aggregation node, please check if ran _get_aggregation() before running _get_topk_pipelet_groups"
        branch_group = []
        branch_tag = BranchCheckResult.TRUE  # whether the whole branch can be one topk group
        branch_bfs_queue: List[CFGnode] = [cfg_node]

        while branch_bfs_queue:
            branch_node = branch_bfs_queue.pop(0)
            if branch_node == cfg_node:
                # current branch node is the start node of the condition branch (if or switch)
                if branch_node.node_type == CFGNodeType.SWITCH:
                    assert len(cfg_node.ir_nodes) > 0, f"Switch node should include ir nodes"
                    ir_node_of_switch = cfg_node.ir_nodes[0]
                    if ir_node_of_switch in topk_pipelet_roots:
                        # TODO: determine the sink of switch table pipelet
                        raise ValueError(f"Temporarily cannot support switch table as topk!")
                        # old code handling topk switch table (return list of pipelet list)
                        # cfg_node.is_mini_topk_component = True
                        # corresponding_topk_pipelet = topk_pipelet_dict[ir_node_of_switch]
                        # branch_group.append([corresponding_topk_pipelet])
                    # else:
                    #     branch_tag = BranchCheckResult.FALSE

                successors = list(cfg_graph.successors(branch_node))
                assert len(successors) > 0, f"If or switch should have successors"
                branch_bfs_queue.extend(successors)

            elif branch_node == aggregation_node:
                if branch_bfs_queue:
                    # There could be multiple appearance of aggregation_node
                    # We just check it for the last appearance
                    continue
                else:
                    if same_tag == False:
                        if branch_node.node_type == CFGNodeType.TABLE:
                            tmp_branch_group = ControlFlowGraph._check_tab_node(
                                branch_node,
                                cfg_graph,
                                irgraph_pipe,
                                branch_group,
                                topk_pipelet_roots,
                                topk_pipelet_dict,
                            )
                            if (
                                branch_tag == BranchCheckResult.TRUE
                            ):  # all other nodes are topk except for the aggregation
                                if branch_node.is_mini_topk_component:  # the whole branch is topk
                                    # each node in the branch has a corresponding list
                                    # we need to combine these list
                                    group_root = cfg_node.ir_nodes[0]
                                    successors = list(cfg_graph.successors(aggregation_node))
                                    assert len(successors) > 0, f"Table node should have one successor"
                                    successor = successors[0]
                                    group_sink = successor.ir_nodes[0]
                                    branch_group = ControlFlowGraph._get_branch_group(
                                        irgraph_pipe, group_root, group_sink, tmp_branch_group
                                    )
                                else:  # check whether the branch without the aggregation can be one smaller topk group
                                    branch_tag = BranchCheckResult.FALSE
                                    check_res = []
                                    check_res = ControlFlowGraph._check_smaller_branch(
                                        cfg_graph, irgraph_pipe, cfg_node, aggregation_node, branch_group
                                    )
                                    branch_tag = check_res[0]
                                    branch_group = check_res[1]
                            elif branch_tag == BranchCheckResult.FALSE:
                                branch_group = tmp_branch_group
                            else:
                                raise ValueError(f"Unexpected BranchCheckResult type: {branch_tag}.")

                            res = []
                            res.append(branch_tag)
                            res.append(branch_group)
                            assert res != None
                            return res

                        elif (
                            branch_node.node_type == CFGNodeType.IF
                            or branch_node.node_type == CFGNodeType.SWITCH
                            or branch_node.node_type == CFGNodeType.SINK
                        ):
                            if branch_tag == BranchCheckResult.TRUE:
                                group_root = cfg_node.ir_nodes[0]
                                group_sink = aggregation_node.ir_nodes[0]
                                branch_group = ControlFlowGraph._get_branch_group(
                                    irgraph_pipe, group_root, group_sink, branch_group
                                )

                            res = []
                            res.append(branch_tag)
                            res.append(branch_group)
                            assert res != None
                            return res

                        else:
                            raise ValueError(f"Unexpected CFGNode type: {branch_node.node_type}.")

                    else:
                        if branch_tag == BranchCheckResult.TRUE:  # all other nodes are topk except for the aggregation
                            check_res = []
                            check_res = ControlFlowGraph._check_smaller_branch(
                                cfg_graph, irgraph_pipe, cfg_node, aggregation_node, branch_group
                            )
                            branch_tag = check_res[0]
                            branch_group = check_res[1]

                            # FALSE means the branch can't generate a smaller group,
                            # but since other nodes except the aggregation node are topk,
                            # the final tag is still TRUE
                            if branch_tag == BranchCheckResult.FALSE:
                                branch_tag = BranchCheckResult.TRUE

                        res = []
                        res.append(branch_tag)
                        res.append(branch_group)
                        assert res != None
                        return res

            else:
                if branch_node.node_type == CFGNodeType.TABLE:
                    branch_group = ControlFlowGraph._check_tab_node(
                        branch_node, cfg_graph, irgraph_pipe, branch_group, topk_pipelet_roots, topk_pipelet_dict
                    )
                    if not branch_node.is_mini_topk_component:
                        branch_tag = BranchCheckResult.FALSE

                    successors = list(cfg_graph.successors(branch_node))
                    assert len(successors) > 0, f"Table node should have successors."
                    branch_bfs_queue.extend(successors)

                elif branch_node.node_type == CFGNodeType.IF or branch_node.node_type == CFGNodeType.SWITCH:
                    if (
                        branch_node.aggregation == None
                    ):  # the sub condition branch shares the aggregation with current branch
                        branch_node.aggregation = aggregation_node
                        res = []
                        res = ControlFlowGraph._check_condition_branch(
                            cfg_graph, irgraph_pipe, branch_node, topk_pipelet_roots, topk_pipelet_dict, True
                        )
                        subbranch_tag = res[0]
                        subbranch_group = res[1]

                        if subbranch_tag == BranchCheckResult.SMALLER:
                            branch_group = ControlFlowGraph._add_subbranch_and_check_larger_branch(
                                cfg_graph, branch_node, branch_group, subbranch_group, topk_pipelet_dict
                            )

                        elif subbranch_tag == BranchCheckResult.TRUE:
                            branch_group.extend(subbranch_group)

                        elif subbranch_tag == BranchCheckResult.FALSE:
                            branch_tag = BranchCheckResult.FALSE
                            branch_group.extend(subbranch_group)

                        else:
                            raise ValueError(
                                f"Unexpected BranchCheckResult type of the sub condition branch {branch_tag}."
                            )

                    else:
                        res = []
                        res = ControlFlowGraph._check_condition_branch(
                            cfg_graph, irgraph_pipe, branch_node, topk_pipelet_roots, topk_pipelet_dict, False
                        )
                        subbranch_tag = res[0]
                        subbranch_group = res[1]

                        if subbranch_tag == BranchCheckResult.TRUE:
                            branch_group = ControlFlowGraph._add_subbranch_and_check_larger_branch(
                                cfg_graph, branch_node, branch_group, subbranch_group, topk_pipelet_dict
                            )

                        elif subbranch_tag == BranchCheckResult.SMALLER:
                            branch_tag = BranchCheckResult.FALSE
                            branch_group = ControlFlowGraph._add_subbranch_and_check_larger_branch(
                                cfg_graph, branch_node, branch_group, subbranch_group, topk_pipelet_dict
                            )

                        elif subbranch_tag == BranchCheckResult.FALSE:
                            branch_tag = BranchCheckResult.FALSE
                            branch_group.extend(subbranch_group)

                        else:
                            raise ValueError(
                                f"Unexpected BranchCheckResult type of the sub condition branch {branch_tag}."
                            )

                    # if the sub aggregation is not the branch aggregation, find and add new successors
                    # else add the shared aggregation
                    sub_aggregation_node = branch_node.aggregation
                    assert sub_aggregation_node != None, f"the sub aggregation has no aggregation node"
                    if sub_aggregation_node != aggregation_node:
                        assert (
                            sub_aggregation_node.depth <= aggregation_node.depth
                        ), f"sub_aggregation_node is deeper than aggregation_node"
                        if sub_aggregation_node.node_type == CFGNodeType.TABLE:
                            successors = list(cfg_graph.successors(sub_aggregation_node))
                            assert (
                                len(successors) > 0
                            ), f"Subbranch aggregation node type is table, it should have successors"
                            branch_bfs_queue.extend(successors)
                        elif (
                            sub_aggregation_node.node_type == CFGNodeType.IF
                            or sub_aggregation_node.node_type == CFGNodeType.SWITCH
                        ):
                            branch_bfs_queue.extend([sub_aggregation_node])
                        else:
                            raise ValueError(
                                f"Unexpected CFGNode type of the sub condition branch aggregation {sub_aggregation_node.node_type}."
                            )
                    else:
                        branch_bfs_queue.extend([sub_aggregation_node])

                else:
                    raise ValueError(
                        f"Unexpected CFGNode type in the middle of the condition branch, unecpected type: {branch_node.node_type}."
                    )

        raise ValueError(f"Abnormal return!")

    @classmethod
    def _get_topk_pipelet_groups(
        cls, irgraph_pipe: IrGraphPipe, cfg_graph: "ControlFlowGraph", topk_pipelet: List[Pipelet]
    ) -> List[PipeletGroup]:

        res = ControlFlowGraph._get_topk_pipelet_roots(topk_pipelet)
        topk_pipelet_roots = res[0]
        topk_pipelet_dict = res[1]

        topk_pipelet_groups: List[PipeletGroup] = []
        cfg_root = cfg_graph.root
        cfg_sink = cfg_graph.sink

        bfs_queue: List[CFGnode] = [cfg_root]
        while bfs_queue:
            cfg_node = bfs_queue.pop(0)
            if cfg_node.node_type == CFGNodeType.ROOT:
                successors = list(cfg_graph.successors(cfg_node))
                assert len(successors) == 1, f"Root should have only one successor"
                bfs_queue.extend(successors)

            elif cfg_node.node_type == CFGNodeType.SINK:
                # There could be multiple appearance of SINK
                # We just ignore it
                # Because it is the length of bfs_queue that determines whether the traversal stops
                continue

            elif cfg_node.node_type == CFGNodeType.TABLE:
                topk_pipelet_groups = ControlFlowGraph._check_tab_node(
                    cfg_node, cfg_graph, irgraph_pipe, topk_pipelet_groups, topk_pipelet_roots, topk_pipelet_dict
                )
                successors = list(cfg_graph.successors(cfg_node))
                assert len(successors) > 0, f"Table node should have successor"
                bfs_queue.extend(successors)

            elif cfg_node.node_type == CFGNodeType.IF or cfg_node.node_type == CFGNodeType.SWITCH:
                # group = []
                assert cfg_node.aggregation != None
                res = ControlFlowGraph._check_condition_branch(
                    cfg_graph, irgraph_pipe, cfg_node, topk_pipelet_roots, topk_pipelet_dict, False
                )
                branch_tag = res[0]
                branch_group = res[1]
                if branch_tag == BranchCheckResult.TRUE:
                    topk_pipelet_groups = ControlFlowGraph._add_subbranch_and_check_larger_branch(
                        cfg_graph, cfg_node, topk_pipelet_groups, branch_group, topk_pipelet_dict
                    )
                elif branch_tag == BranchCheckResult.SMALLER:
                    topk_pipelet_groups = ControlFlowGraph._add_subbranch_and_check_larger_branch(
                        cfg_graph, cfg_node, topk_pipelet_groups, branch_group, topk_pipelet_dict
                    )
                elif branch_tag == BranchCheckResult.FALSE:
                    topk_pipelet_groups.extend(branch_group)

                else:
                    raise ValueError(f"Unexpected BranchCheckResult type in the condition branch {branch_tag}.")

                aggregation_node = cfg_node.aggregation
                if aggregation_node.node_type == CFGNodeType.TABLE:
                    # table type was checked, so then check the successors of aggregation node
                    successors = list(cfg_graph.successors(aggregation_node))
                    assert len(successors) > 0, f"Table (aggregation node) should have successor"
                    bfs_queue.extend(successors)
                else:
                    # other types were not checked, so then check the aggregation node
                    bfs_queue.append(aggregation_node)

            else:
                raise ValueError(f"Unexpected CFGNode type {cfg_node.node_type}.")

        return topk_pipelet_groups
