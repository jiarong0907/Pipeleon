import itertools
import json
import os
import sys
from copy import deepcopy
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type, Union

sys.path.insert(0, os.path.abspath("./src"))

from graph_optimizer.metadata import (
    CacheMetadata,
    ExtensionMetadata,
    GroupCacheMetadata,
    MergeMetadata,
    SoftcopyMetadata,
    SoftmoveMetadata,
)
from graph_optimizer.reconnector import Reconnector
from ir.general_table import GeneralTable
from ir.ir_node import Root
from ir.opt_table import OptTable

import commons.config as config
from commons.constants import (
    EARLY_TERM_PRIM,
    MAX_COND,
    SEGMENT_OPT_ALPHA,
    TESTING_SPLIT,
    ActionType,
    CFGNodeType,
    DeviceTargetType,
    OptimizeTarget,
    OptimizedType,
)
from graph_optimizer.options import *
from graph_optimizer.pipelet import Pipelet, PipeletGroup
from graph_optimizer.runtime_states import (
    ActionMeta,
    CondCountProfile,
    TableCountProfile,
    RuntimeStates,
    TableMeta,
)
from ir.action import Action, OptAction
from ir.condition import Condition
from commons.types import ActionInfoMap, ConstEntries, TableId, TableName
from ir.irgraph import IrGraph
from ir.irgraph_pipe import IrGraphPipe, IrNode, Sink
from ir.table import Table
from ir.match_key import MatchKey
from ir.next_table_selector import NextTableSelector
from commons.metric import MetricParams
from targets.smart_nic import SmartNic
from targets.target_base import MultiTargetBase
from commons.base_logging import logger
import commons.base_warnning as base_warnning


class CopyManager:
    # the igraph_pipe pool created for avoiding deepcopy
    _irgpipe_pool: List[IrGraphPipe] = []

    @classmethod
    def _copy_pipelet(cls, pipelet: Pipelet) -> Pipelet:
        if len(cls._irgpipe_pool) == 0:
            logger.warning(
                f"The irgraph_pipe pool is empty, using deepcopy instead. " f"This will affect the performance."
            )
            return deepcopy(pipelet)
        else:
            irgraph_pipe = cls._irgpipe_pool.pop()
            pipelets = JsonPlanner.get_pipelets(irgraph_pipe)
            for p in pipelets:
                if p.root.name == pipelet.root.name:
                    return p
            assert False, f"The pipelet {pipelet.root.name} was not found in the cache."


class JsonManager:
    """JsonManager - JsonPlanner, JsonDeployer arch
    JsonManager: The main entry class for managing json
    JsonPlanner: A class JsonManager used to label IR before final deployment
    JsonDeployer: A class JsonManager used to convert the json into
        ready-to-run multi-target jsons and save the result (including mapping) back to
        the NIC
    """

    def __init__(self, api):
        self._api = api
        self._json_planner = JsonPlanner(api)
        self._json_deployer = JsonDeployer(api)

    @staticmethod
    def retrieve_presplit(input_json_path: str) -> Tuple[IrGraph, SmartNic]:
        """
        Read json from given path and return the irg and target
        """
        irg = IrGraph.import_p4cirjson(path=input_json_path)
        target = SmartNic()
        irg.assign_target(target)

        return (irg, target)

    def retrieve_runtime_states(
        self,
        json_file: str,
        mapping_file: Optional[str] = None,
    ) -> RuntimeStates:
        """Retrieve runtime states

        Args:
            json_file: The file name of input json storing the targeting bmv2
                json
            mapping_file: The file name of output mapping dictionary. If
                not specified, a tmp.json path will be used to save the
                mapping json file temporarily.
        """
        if mapping_file is None:
            mapping_file = "tmp_mapping.json"

        with open(json_file, "r") as f:
            json_str = f.read()
            running_json = json.loads(json_str)
            cxt_id = 0  # Always use contxt 0 for FlexSwitch bmv2 (the NIC will find the right context)

            action_to_meta: Dict[int, ActionMeta] = {}
            for action in running_json.get("actions", []):
                action_to_meta[action["id"]] = ActionMeta(action["name"], action["id"])

            table_to_meta: Dict[str, TableMeta] = {}
            table_to_size: Dict[str, int] = {}
            table_to_entry_insertion_count: Dict[str, int] = {}
            for pipeline in running_json.get("pipelines", []):
                for table in pipeline.get("tables", []):
                    table_name = table["name"]
                    for action_id in table["action_ids"]:
                        assert not hasattr(action_to_meta[action_id], "table_name"), (
                            f"We assume no action id is shared by multiple tables,"
                            f"but we got action id {action_id} twice from tables"
                            f"{action_to_meta[action_id].table_name} and {table_name}"
                        )
                        action_to_meta[action_id].set_table_info(table_name)
                    table_to_meta[table_name] = TableMeta(table["action_ids"])
                    table_to_size[table_name] = self._api.client.bm_mt_get_num_entries_from_mapping(table_name)
                    table_to_entry_insertion_count[table_name] = self._api.client.bm_mt_entry_insertion_counter_read(
                        table_name
                    )
                    self._api.client.bm_mt_entry_insertion_counter_reset(table_name)

            table_to_counts: Dict[str, TableCountProfile] = {}
            counter_name = "$flex_action_counter"
            for action in running_json.get("actions", []):
                action_id = action["id"]
                action_name = action["name"]
                table_name: TableName = action_to_meta[action_id].table_name

                # Get the count with RuntimeAPI
                print(f"Reading counter {counter_name} at index {action_id} in cxt {cxt_id}")
                value = self._api.client.bm_counter_read(cxt_id, counter_name, action_id)
                print(f"The result of reading counter: {value}")
                count = value.packets
                if table_name not in table_to_counts:
                    table_to_counts[table_name] = TableCountProfile()
                table_to_counts[table_name].counts[action_id] = count
                table_to_counts[table_name].action_meta[action_id] = action_to_meta[action_id]

                assert (
                    table_name in table_to_counts and action_id in table_to_counts[table_name].counts
                ), f"action {action_name} does not have a flex_tab_counter"
                if len(EARLY_TERM_PRIM & {primitive["op"] for primitive in action.get("primitives", [])}) > 0:
                    table_to_counts[table_name].drop_count += count
            self._api.client.bm_counter_reset_all(cxt_id, counter_name)

            cond_to_counts: Dict[int, CondCountProfile] = {}
            counter_name = "$flex_cond_counter"
            BRANCH_METADATA = [  # branch_name, id_offset
                ("true", 0),
                ("false", 1),
            ]
            for pipe in running_json.get("pipelines", []):
                # Assuming conditionals' ids are unique across pipelines
                # TODO: Need to check
                for cond in pipe.get("conditionals", []):
                    cond_id = cond["id"]
                    cond_name = cond["name"]
                    for branch_name, id_offset in BRANCH_METADATA:
                        branch_id = cond_id * 2 + id_offset

                        # Get the count with RuntimeAPI
                        print(f"Reading counter {counter_name} at index {branch_id} in cxt {cxt_id}")
                        value = self._api.client.bm_counter_read(cxt_id, counter_name, branch_id)
                        print(f"The result of reading counter: {value}")
                        count = value.packets
                        if cond_name not in cond_to_counts:
                            cond_to_counts[cond_name] = CondCountProfile()
                        cond_to_counts[cond_name].counts[branch_name] = count

                        assert (
                            cond_name in cond_to_counts and branch_name in cond_to_counts[cond_name].counts
                        ), f"{branch_name} branch of {cond_name} does not have a flex_cond_counter"
            self._api.client.bm_counter_reset_all(cxt_id, counter_name)

            mtotal = self._api.client.bm_get_total_memory(cxt_id)
            itotal = self._api.client.bm_get_total_entry_insertion_bandwidth(cxt_id)
            self._api.client.bm_mt_get_mapping(mapping_file)
            with open(mapping_file, "r") as f:
                json_str = f.read()
                mapping_dict = json.loads(json_str)
                assert mapping_dict["status"] == "reoptimizing", (
                    f"Retrieved mapping from bmv2 should have status "
                    f"'reoptimizing', but we got {mapping_dict['status']}"
                )

            return RuntimeStates(
                table_to_counts,
                cond_to_counts,
                table_to_size,
                table_to_entry_insertion_count,
                mtotal,
                itotal,
                mapping_dict,
            )

    @staticmethod
    def compile_time_json_planning(presplit_irg: IrGraph) -> None:
        # Note that mark_unsupported_nodes must be called first; otherwise it will
        # over-write the results produced by mark_semisupported_nodes
        JsonPlanner.mark_unsupported_nodes(presplit_irg)
        JsonPlanner.mark_semisupported_nodes(presplit_irg)

    @staticmethod
    def from_plan_labeling_to_single_json(
        target: MultiTargetBase,
        presplit_irg: IrGraph,
    ) -> Dict[str, Any]:
        JsonDeployer.prepare_optimizer_created_tables(presplit_irg)
        JsonDeployer.from_optimized_type_to_target_type(presplit_irg)
        mapping_dict = JsonDeployer.gen_table_mapping_dict(
            presplit_irg,
            target,
        )
        return mapping_dict

    @staticmethod
    def from_single_json_to_multitarget_jsons(
        target: MultiTargetBase, presplit_irg: IrGraph
    ) -> Dict[DeviceTargetType, IrGraph]:
        JsonDeployer._add_flex_cond_counter(presplit_irg)
        target2irg = JsonDeployer.connect_extension_copy_tables(target, presplit_irg)
        return target2irg

    def deploy_new_multitarget_jsons(
        self,
        target: MultiTargetBase,
        target2irg: Dict[DeviceTargetType, IrGraph],
        mapping_dict: Dict[str, Any],
        presplit_preopt_irg: IrGraph,
        input_json_path: str,
        round: int,
    ) -> None:
        changed = self._json_deployer.invoke_flexcore_set_mapping(target, target2irg, mapping_dict, round)
        if changed:
            # store the json back before split after optimization if changed
            JsonDeployer.store_presplit(presplit_preopt_irg, input_json_path)

    @staticmethod
    def try_reordering(
        pipelet: Pipelet,
        plan: List[int],
    ) -> MetricParams:
        """Try a reordering plan on a specific pipelet on the current graph and
        return trial result.

        The current graph will be untouched, we will try the plan on a copy.
        Return:
            trial result includes latency, throughput, and memory usage
        """
        base_warnning.raise_deprecated_warning("This is going to be deprecated.")
        # Copy the graph and the pipelet
        new_pipelet = deepcopy(pipelet)

        # Apply the plan on the copy
        JsonPlanner.apply_reordering(new_pipelet, ReorderOption(plan))

        # optimizations needs to be instantiated rather than just labeling
        JsonManager.from_plan_labeling_to_single_json(
            new_pipelet.irgraph_pipe.target,
            new_pipelet.irgraph_pipe.ir_graph,
        )

        # Run simulation on the copy and return the result
        return new_pipelet.irgraph_pipe.eval()

    @staticmethod
    def try_segment_opt(
        pipelet: Pipelet,
        plan: SegmentOptimizationOption,
    ) -> MetricParams:
        """Try a segment-based optimization plan on a specific pipelet on the
        current graph and return trial result.

        The current graph will be untouched, we will try the plan on a copy.
        Return:
            trial result includes latency, throughput, and memory usage
        """
        base_warnning.raise_deprecated_warning("This is going to be deprecated.")
        # Copy the graph and the pipelet
        new_pipelet = deepcopy(pipelet)

        # Apply the plan on the copy
        JsonPlanner.apply_segment_opt(new_pipelet, plan)

        # optimizations needs to be instantiated rather than just labeling
        JsonManager.from_plan_labeling_to_single_json(
            new_pipelet.irgraph_pipe.target, new_pipelet.irgraph_pipe.ir_graph
        )

        # Run simulation on the copy and return the result
        return new_pipelet.irgraph_pipe.eval()


class JsonPlanner:
    def __init__(self, api):
        self._api = api

    @staticmethod
    def get_pipelets(graph: IrGraphPipe) -> List[Pipelet]:
        """Get a list of pipelets with recursive function to traverse the
        IrGraphPipe (a graph)
        """
        pipelet_start = graph.get_init_table()
        pipelets: Set[Pipelet] = set()
        JsonPlanner._rec_create_pipelets(graph, pipelet_start, pipelets, visited=[])
        return list(pipelets)

    @staticmethod
    def get_topk_pipelets(
        pipelets: List[Pipelet], topk: float, optimize_target: OptimizeTarget  # range=(0, 1)
    ) -> List[Pipelet]:
        """Get the top-k bottlenecked pipelets"""
        assert 0 < topk <= 1, f"top-k should be between 0 and 1."
        idx_metric: List[Tuple[int, float]] = []
        for i in range(len(pipelets)):
            pipelet_copy = CopyManager._copy_pipelet(pipelets[i])
            # re-split the original pipelet before we evaluate it
            JsonPlanner._resplit_irg_pipe(pipelet_copy.irgraph_pipe)
            eval_metric = pipelet_copy.eval()
            if optimize_target == OptimizeTarget.LATENCY:
                idx_metric.append((i, eval_metric._average_latency))
            elif optimize_target == OptimizeTarget.THROUGHT:
                idx_metric.append((i, eval_metric._inter_packet_gap))
            else:
                raise NotImplementedError(f"{optimize_target} is not implemented!")
        # select the topk pipelets
        idx_metric.sort(key=lambda item: (item[1], item[0]), reverse=True)
        topk_pipelets: List[Pipelet] = []
        topk_num = max(int(len(pipelets) * topk), 1)
        for i in range(topk_num):
            topk_pipelets.append(pipelets[idx_metric[i][0]])

        for idx_m in idx_metric:
            logger.info((pipelets[idx_m[0]].root.name, idx_m[1]))
        return topk_pipelets

    @staticmethod
    def _resplit_irg_pipe(irg_pipe: IrGraphPipe):
        assert irg_pipe.target is not None, f"Target has not been assigned."
        JsonManager.from_plan_labeling_to_single_json(irg_pipe.target, irg_pipe.ir_graph)

    @staticmethod
    def _rec_create_pipelets(
        graph: IrGraphPipe, pipelet_start: IrNode, pipelets: Set[Pipelet], visited: List[TableName]
    ):
        """Recursively find all pipelets starting from pipelet_start, and store
        the pipelets as recursion goes"""

        # Find the end of the current pipelet and the mapping from
        # in-pipelet-id to node name
        if pipelet_start.name in visited:
            return
        next_start = pipelet_start
        count = 0
        logger.debug(f"pipelet_start: {pipelet_start}")
        while True:
            predecessors = list(graph.predecessors(next_start))
            successors = list(graph.successors(next_start))
            logger.debug(f"predecessors: {[t.name for t in predecessors]}")
            logger.debug(f"successors: {[t.name for t in successors]}")
            if len(successors) == 1 and (len(predecessors) == 1 or next_start == pipelet_start):
                logger.debug(f"current node: {next_start}, next node: {successors[0]}")
                count += 1
                next_start = successors[0]
            else:
                break

        # for single node pipelet
        if count == 0:
            # filter out if-else conditions and Sink
            if isinstance(pipelet_start, Table):
                visited.append(pipelet_start.name)
                pipelets.add(Pipelet(graph, pipelet_start, 1))

            for new_next_start in list(graph.successors(pipelet_start)):
                JsonPlanner._rec_create_pipelets(graph, new_next_start, pipelets, visited)
        else:
            visited.append(pipelet_start.name)
            pipelets.add(Pipelet(graph, pipelet_start, count))
            JsonPlanner._rec_create_pipelets(graph, next_start, pipelets, visited)

    @staticmethod
    def get_pipelet_groups(
        irgraph_pipe: IrGraphPipe, topk_pipelets: List[Pipelet], all_pipelets: List[Pipelet]
    ) -> List[PipeletGroup]:
        """A wrapper function to merge pipelet into groups"""

        all_pipelet_starts = {pipelet.root.name: pipelet for pipelet in all_pipelets}
        topk_pipelet_starts = {pipelet.root.name: pipelet for pipelet in topk_pipelets}
        graph_root = irgraph_pipe.root
        assert graph_root != None, f"The graph root is None. Cannot find pipelet groups"
        all_groups: Set[PipeletGroup] = set()
        _, res = JsonPlanner._rec_merge_pipelets(
            irgraph_pipe=irgraph_pipe,
            group_root=irgraph_pipe.root,
            topk_pipelet_starts=topk_pipelet_starts,
            all_pipelet_starts=all_pipelet_starts,
            all_groups=all_groups,
        )
        return list(res)

    @staticmethod
    def _merge_multi_pipelet_groups(
        irgraph_pipe: IrGraphPipe,
        group_root: Union[IrNode, Root],
        to_merge: List[PipeletGroup],  # groups need to be merged
    ):
        # get pipelets from children
        new_group_pipelets: List[Pipelet] = list(itertools.chain(*[group.pipelets for group in to_merge]))

        # check that all PipeletGroups have the same sink
        for pg in to_merge:
            assert pg.sink.name == to_merge[0].sink.name, (
                f"all PipeletGroups should have the same sink, but the sink name "
                f"of this one is {pg.sink.name} and that of the first one is "
                f"{to_merge[0].sink.name}"
            )
        return PipeletGroup(
            irgraph_pipe=irgraph_pipe, root=group_root, sink=to_merge[0].sink, pipelets=new_group_pipelets
        )

    @staticmethod
    def _create_single_pipelet_group(
        irgraph_pipe: IrGraphPipe,
        pipelet: Pipelet,
    ) -> Union[PipeletGroup, None]:
        pipelet_succ: List[IrNode] = list(irgraph_pipe.successors(pipelet.sink))
        # switch table cannot be a group alone
        if pipelet.length == 1 and len(pipelet_succ) > 1:
            return None
        return PipeletGroup(irgraph_pipe=irgraph_pipe, root=pipelet.root, sink=pipelet_succ[0], pipelets=[pipelet])

    @staticmethod
    def _merge_single_pipelet_with_children(
        irgraph_pipe: IrGraphPipe, pipelet: Pipelet, is_children_mergeable: bool, all_groups: Set[PipeletGroup]
    ) -> None:
        pipelet_succ: List[IrNode] = list(irgraph_pipe.successors(pipelet.sink))
        # add this single pipelet as a group
        if not is_children_mergeable:
            new_pipelet_group = JsonPlanner._create_single_pipelet_group(irgraph_pipe, pipelet)
            if new_pipelet_group is not None:
                all_groups.add(new_pipelet_group)
            return

        # merge this single pipelet with its children
        # regular pipelet
        if len(pipelet_succ) == 1:
            # No children to merge, just add this pipelet as a group
            if pipelet_succ[0].name == Sink.name:
                new_pipelet_group = JsonPlanner._create_single_pipelet_group(irgraph_pipe, pipelet)
                if new_pipelet_group is not None:
                    all_groups.add(new_pipelet_group)
                return

            # merge with children, need to make sure it is the only predecessor of
            # the children
            pipelet_succ_pred: List[IrNode] = list(irgraph_pipe.predecessor(pipelet_succ[0]))
            if len(pipelet_succ_pred) > 1:
                return

            to_merge: List[PipeletGroup] = []  # groups need to be merged
            to_keep: Set[PipeletGroup] = set()  # groups should not be touched
            for group in all_groups:
                # to handle switch table
                if pipelet_succ[0].name == group.root.name:
                    to_merge.append(group)
                else:
                    to_keep.add(group)
            assert len(to_merge) == 1, f"There should be one child PipeletGroup to merge, " f"but got {len(to_merge)}."

            to_keep.add(JsonPlanner._merge_multi_pipelet_groups(irgraph_pipe, pipelet.root, to_merge))
            all_groups = to_keep
            return

        # switch table pipelet
        to_merge: List[PipeletGroup] = []  # groups need to be merged
        to_keep: Set[PipeletGroup] = set()  # groups should not be touched
        for group in all_groups:
            for succ in pipelet_succ:
                if succ.name == group.root.name:
                    to_merge.append(group)
        to_keep = set(group for group in all_groups if group not in to_merge)

        # not all children are mergeable
        if len(to_merge) != len(pipelet_succ):
            return

        # all children are mergeable, need to make sure it is the only
        # predecessor of all children
        for succ in pipelet_succ:
            pipelet_succ_pred: List[IrNode] = list(irgraph_pipe.predecessor(succ))
            if len(pipelet_succ_pred) > 1:
                return

        # pass all check, merge
        to_keep.add(JsonPlanner._merge_multi_pipelet_groups(irgraph_pipe, pipelet.root, to_merge))
        all_groups = to_keep

    @staticmethod
    def _rec_merge_pipelets(
        irgraph_pipe: IrGraphPipe,
        group_root: Union[IrNode, Root],
        topk_pipelet_starts: Dict[TableName, Pipelet],
        all_pipelet_starts: Dict[TableName, Pipelet],
        all_groups: Set[PipeletGroup],
    ) -> Tuple[bool, Set[PipeletGroup]]:
        """Recursively merge pipelets by dfs over the graph. A group can be created with a
        specific root if all the children of the root have their own groups
        """
        if isinstance(group_root, Sink):
            return (True, all_groups)

        successors: List[IrNode] = list(irgraph_pipe.successors(group_root))
        flag_mergeable = True
        for succ in successors:
            res, groups = JsonPlanner._rec_merge_pipelets(
                irgraph_pipe, succ, topk_pipelet_starts, all_pipelet_starts, all_groups
            )
            all_groups = groups
            flag_mergeable = flag_mergeable & res
            # Sink
            if isinstance(succ, Sink):
                # Sink is the only child
                if len(successors) == 1:
                    return (True, all_groups)
                continue
            # pipelet internal node
            elif isinstance(succ, Table) and succ.name not in all_pipelet_starts:
                return (flag_mergeable, all_groups)
            # pipelet head, but not a top-k pipelet
            elif succ.name in all_pipelet_starts and succ.name not in topk_pipelet_starts:
                flag_mergeable = False
            # pipelet head, but it is in a top-k pipelet
            elif succ.name in topk_pipelet_starts:
                JsonPlanner._merge_single_pipelet_with_children(
                    irgraph_pipe, topk_pipelet_starts[succ.name], res, all_groups
                )
            elif isinstance(succ, Condition):
                continue
            else:
                assert False
        # all children are in top-k, we can merge them into a larger group
        if flag_mergeable:
            to_merge: List[PipeletGroup] = []  # groups need to be merged
            to_keep: Set[PipeletGroup] = set()  # groups should not be touched
            num_sink_children = 0

            for succ in successors:
                if isinstance(succ, Sink):
                    num_sink_children += 1
                    continue
                for group in all_groups:
                    if succ.name == group.root.name:
                        to_merge.append(group)

            to_keep = set(group for group in all_groups if group not in to_merge)

            assert len(to_merge) + num_sink_children == len(successors), (
                f"All children must be mergeable, but {group_root.name} have "
                f"{len(successors)} chidlren and {len(to_merge)} are mergeable "
                f"and {num_sink_children} are Sink"
            )

            to_keep.add(JsonPlanner._merge_multi_pipelet_groups(irgraph_pipe, group_root, to_merge))
            all_groups = to_keep
            return (flag_mergeable, all_groups)
        return (False, all_groups)

    @staticmethod
    def _compute_reorder_plan_simple(pipelet: Pipelet, table_to_counts: Dict[str, TableCountProfile]) -> ReorderOption:
        """Compute the reorder plan for a given pipelet

        The output list has the following rule: table at location 0 will be
        reordered to location 1 if list[1] is 0
        """
        base_warnning.raise_deprecated_warning("This is going to be deprecated.")
        # TODO: This does not consider data dependency
        # Create mapping between id and table name
        id_to_name = {}
        next_start = pipelet.root
        for id in range(0, pipelet.length):
            id_to_name[id] = next_start.name
            successors = list(pipelet.irgraph_pipe.successors(next_start))
            assert len(successors) == 1, (
                f"Node in a pipelet should have a single successor, but node "
                f"{next_start} has multiple: {successors}"
            )
            next_start = successors[0]

        best_plan = ReorderOption(
            sorted(
                list(range(0, pipelet.length)),
                key=lambda x: table_to_counts[id_to_name[x]].drop_count,
                reverse=True,
            )
        )

        return best_plan

    @staticmethod
    def _compute_segment_opt_plan_simple(
        pipelet: Pipelet,
        table_to_counts: Dict[str, TableCountProfile],
        option_cls: Type[SegmentOptimizationOption],
    ) -> Optional[SegmentOptimizationOption]:
        """Compute the segment-based optimization plan for a given pipelet"""
        base_warnning.raise_deprecated_warning("This is going to be deprecated.")
        # collect the starting subtargets (as number) for all tables
        # in the pipelet
        plan: List[OptimizedType] = pipelet.table_optimized_types
        tables = pipelet.tables

        # We identify all segments with continuous zeros that are enclosed by
        # two non-zero numbers. These segments are candidates for us to decide
        # whether to perform the segment-based optimization. The heuristic for
        # now is to treat number of tables in the segments as cost (C), and
        # percentage of traffic flowing through the segment as benefit (B),
        # and we decide to perform the optimization on the segment if B *
        # alpha > C, where alpha is set to 2.

        def _check_and_mark_seg_opt(num_zeros, cur_mig_percentage, plan, last_non_zero, found):
            if cur_mig_percentage * SEGMENT_OPT_ALPHA > num_zeros:  # B * alpha > C
                # Collect the current segment and mark them "copied/cached/merged"
                for j in range(num_zeros):
                    # we use merged as a type to represent copied/cached/merged
                    plan[last_non_zero + 1 + j] = OptimizedType.MERGED
                return True
            else:
                print(
                    f"The segment is not optimized, several parameters are: "
                    f"cur_mig_percentage: {cur_mig_percentage}, "
                    f"num_zeros: {num_zeros}"
                )
                return found

        cur_mig_percentage = 0
        last_non_zero = -1
        found = False
        for i in range(0, len(plan)):
            if plan[i] != OptimizedType.HW_STEERING:
                num_zeros = i - last_non_zero - 1
                found = _check_and_mark_seg_opt(num_zeros, cur_mig_percentage, plan, last_non_zero, found)

                # Prepare for the next segment
                last_non_zero = i
                if plan[i] == OptimizedType.SW_STEERING:
                    cur_mig_percentage = 1
                elif plan[i] == OptimizedType.SEMI_SUPPORTED:
                    cur_mig_percentage = JsonPlanner._calculate_traffic_percentage(tables[i], table_to_counts)
        if plan[-1] == OptimizedType.HW_STEERING:
            num_zeros = len(plan) - last_non_zero - 1
            found = _check_and_mark_seg_opt(num_zeros, cur_mig_percentage, plan, last_non_zero, found)

        if not found:
            return None
        # To adapt to the SegmentOptimizationOption format, we only choose the first segment
        start_table_id = -1
        length = 0
        for i in range(len(plan)):
            if start_table_id != -1 and plan[i] != OptimizedType.MERGED:
                if length == 1 and option_cls == MergeOption:
                    # For MergeOption, we need at least two tables
                    start_table_id = -1
                    length = 0
                else:
                    break
            elif start_table_id == -1 and plan[i] == OptimizedType.MERGED:
                start_table_id = i
                length = 1
            elif start_table_id != -1 and plan[i] == OptimizedType.MERGED:
                length += 1
        return option_cls(start_table_id, length)

    @staticmethod
    def apply_reordering(pipelet: Pipelet, order_option: ReorderOption):
        """order[0] == 3 means the 3rd node in the original pipelet should be put at the 0 place"""
        order = order_option.new_table_pos
        if len(order) <= 1:
            return
        logger.debug(f"New order: {order}")
        # collect all nodes in the pipelet in the original order
        graph = pipelet.irgraph_pipe
        nodes_in_original_order = pipelet.tables
        pipelet_pred = list(graph.predecessors(nodes_in_original_order[0]))
        pipelet_succ = list(graph.successors(nodes_in_original_order[-1]))
        assert pipelet_pred != None and pipelet_succ != None and len(pipelet_succ) == 1
        pipelet_succ = pipelet_succ[0]

        # set edges
        orig_node = nodes_in_original_order[0]
        new_node = nodes_in_original_order[order[0]]
        for pred in pipelet_pred:
            graph.change_next_node_in_pipelet(pred, new_node, orig_node)
        for place in range(0, len(order)):
            node = nodes_in_original_order[order[place]]
            if place == len(order) - 1:
                succ = pipelet_succ
            else:
                succ = nodes_in_original_order[order[place + 1]]
            graph.change_next_node_in_pipelet(node, succ)

        pipelet.root = new_node
        graph.refresh_edges()

    @staticmethod
    def _calculate_traffic_percentage(table: Table, table_to_counts: Dict[str, TableCountProfile]) -> float:
        base_warnning.raise_deprecated_warning("This is going to be deprecated.")
        unsupported_action_ids = table.unsupported_action_ids
        counters = table_to_counts[table.name]
        print(f"during compute traffic perentage, the counts: {counters}")
        total_count = 0
        unsupported_count = 0
        for action_meta in counters.action_meta.values():
            action_id = action_meta.action_id
            total_count += counters.counts[action_id]
            if action_id in unsupported_action_ids:
                unsupported_count += counters.counts[action_id]
        return 0 if total_count == 0 else unsupported_count / total_count

    @staticmethod
    def apply_segment_opt(pipelet: Pipelet, plan: SegmentOptimizationOption):
        """modify the pipelet to place each table based on the input
        segment-based optimization plan

        Each option has the following two fields:
            - start_table_id: We start copying tables to software from here
            - length: The number of consecutive tables we want to copy
        """
        logger.debug(f"{plan.__class__.__name__}: start_table_id={plan.start_table_id}, " f"length={plan.length}")
        # collect all nodes in the pipelet
        tables = pipelet.tables
        for i in range(plan.length):
            node = tables[i + plan.start_table_id]
            if isinstance(plan, SoftcopyOption):
                node.optimized_type = OptimizedType.COPIED
                node.optimized_metadata = SoftcopyMetadata(plan.start_table_id, plan.length, node)
            elif isinstance(plan, SoftmoveOption):
                node.optimized_type = OptimizedType.SW_STEERING
                node.optimized_metadata = SoftmoveMetadata(plan.start_table_id, plan.length)
            elif isinstance(plan, CacheOption):
                node.optimized_type = OptimizedType.CACHED
                node.optimized_metadata = CacheMetadata(
                    plan.start_table_id,
                    plan.length,
                    cached_tables=pipelet.tables[plan.start_table_id : plan.start_table_id + plan.length],
                )
            elif isinstance(plan, MergeOption):
                node.optimized_type = OptimizedType.MERGED
                node.optimized_metadata = MergeMetadata(
                    plan.start_table_id,
                    plan.length,
                    merged_tables=pipelet.tables[plan.start_table_id : plan.start_table_id + plan.length],
                )
            else:
                logger.ERROR(f"Unknown segment optimization option: " f"{plan.__class__.__name__}")

    @staticmethod
    def apply_group_merge(pipe_grp: PipeletGroup):
        raise NotImplementedError(f"Currently not support group merge.")

    @staticmethod
    def apply_group_cache(pipe_grp: PipeletGroup):
        """modify the pipelet to place each table based on the input
        segment-based optimization plan
        """
        # collect all nodes in the pipelet
        for node in pipe_grp.nodes:
            if config.GROUP_CACHE_ENABLED:
                if not (isinstance(node, Table) or isinstance(node, Condition)):
                    continue
            else:
                if not isinstance(node, Table):
                    continue
            node.optimized_type = OptimizedType.GROUP_CACHED
            node.optimized_metadata = GroupCacheMetadata(
                pipe_grp=pipe_grp, root=pipe_grp.root, sink=pipe_grp.sink, cached_tables=pipe_grp.nodes
            )

    @staticmethod
    def run_opt_reordering(pipelet: Pipelet, table_to_counts: Dict[str, TableCountProfile]):
        plan = JsonPlanner._compute_reorder_plan_simple(pipelet, table_to_counts)
        JsonPlanner.apply_reordering(pipelet, plan)

    @staticmethod
    def run_opt_segment(
        pipelet: Pipelet,
        table_to_counts: Dict[str, TableCountProfile],
        option_cls: Type[SegmentOptimizationOption],
    ) -> None:
        plan = JsonPlanner._compute_segment_opt_plan_simple(pipelet, table_to_counts, option_cls)
        if plan:
            JsonPlanner.apply_segment_opt(pipelet, plan)

    @staticmethod
    def get_all_plans(
        pipelet: Pipelet,
        option_cls: Type[SegmentOptimizationOption],
    ) -> List[SegmentOptimizationOption]:
        optimized_types = pipelet.table_optimized_types
        # We identify all segments with continuous zeros that are enclosed by
        # two non-zero numbers. These segments are candidates for us to decide
        # whether to create a copy / cache / merge table.

        base_warnning.raise_deprecated_warning("This is going to be deprecated.")

        all_plans: List[option_cls] = []
        start_id, length = -1, 0
        for i in range(len(optimized_types)):
            if optimized_types[i] == OptimizedType.HW_STEERING and start_id == -1:
                start_id, length = i, 1
                continue
            if optimized_types[i] == OptimizedType.HW_STEERING:
                length += 1
            elif length > 0:
                if not (length == 1 and option_cls in [MergeOption]):
                    # For MergeOption, we need at least two tables
                    all_plans.append(option_cls(start_id, length))
                start_id, length = -1, 0
        if length > 0:
            if not (length == 1 and option_cls in [MergeOption]):
                # For MergeOption, we need at least two tables
                all_plans.append(option_cls(start_id, length))
        return all_plans

    @staticmethod
    def mark_unsupported_nodes(ir_graph: IrGraph):
        """
        Assigns all nodes without range field to target_name, and the rest to the default target.
        This must be done first because calling mark_semisupported_nodes.
        """
        for pipe in [ir_graph.get_pipe(p) for p in ir_graph.get_pipe_names()]:
            for node in pipe.normal_nodes:
                if isinstance(node, Condition):
                    node.optimized_type = OptimizedType.HW_STEERING
                elif isinstance(node, Table):
                    match_type = node._p4cjson_description["match_type"]
                    if match_type != "range":
                        node.optimized_type = OptimizedType.HW_STEERING
                    else:
                        logger.debug(f"Node {node} has range fields")
                        node.optimized_type = OptimizedType.SW_STEERING

    @staticmethod
    def mark_semisupported_nodes(ir_graph: IrGraph):
        """
        identify unsupported actions and mark tables as arm-only
        (subtarget_names[1]) or semi-supported accordingly.
        This must be done later than mark_unsupported_nodes.
        """
        for pipe in [ir_graph.get_pipe(p) for p in ir_graph.get_pipe_names()]:
            for node in pipe.normal_nodes:
                # Only need to check tables that are still in asic
                if (not isinstance(node, Table)) or node.optimized_type != OptimizedType.HW_STEERING:
                    continue

                # Identify unsupported actions
                unsupported_actions = []
                has_supported_actions = False
                for (action, _) in node.action_iterator:
                    # print(action_name, primitives)
                    if Table.has_unsupported_primitives(action.primitives):
                        unsupported_actions.append(action.name)
                    else:
                        has_supported_actions = True

                # fully unsupported tables => just move the table to ARM subtarget
                if (not has_supported_actions) and len(unsupported_actions) != 0:
                    logger.debug(f"Node {node} is fully unsupported")
                    node.optimized_type = OptimizedType.SW_STEERING

                # semi-supported tables => mark it as semi-supported temporarily
                # for prepare_optimizer_created_tables()
                elif has_supported_actions and len(unsupported_actions) != 0:
                    logger.debug(f"Node {node} is semi-supported")
                    node.optimized_type = OptimizedType.SEMI_SUPPORTED
                    node.optimized_metadata = ExtensionMetadata(-1, -1, node)


class JsonDeployer:
    def __init__(self, api):
        self._api = api

    @staticmethod
    def store_presplit(irg, export_path: str):
        """write the irg to json file"""
        irg.export_p4cirjson(path=export_path)
        assert os.path.exists(export_path)

    @staticmethod
    def prepare_optimizer_created_tables(ir_graph: IrGraph):
        """
        Create extra tables for optimizations.

        Including extension tables for unsupported actions, copy, cache, and
        merge tables after runtime optimizations. Insert edges before these
        tables.
        """
        for pipe in [ir_graph.get_pipe(p) for p in ir_graph.get_pipe_names()]:
            name_to_new_node: Dict[str, OptTable] = {}
            name_to_removing_node: Dict[str, Table] = {}
            for node in pipe.normal_nodes:
                # Only need to check tables that are semi-supported or
                # runtime-optimized, so skip non-table nodes

                if config.GROUP_CACHE_ENABLED:
                    if not (isinstance(node, Table) or isinstance(node, Condition)):
                        continue
                else:
                    if not isinstance(node, Table):
                        continue

                node.prepare_optimizer_created_tables(ir_graph, pipe, name_to_new_node, name_to_removing_node)
            # print([(node.name, node._actions) for node in new_nodes])

            # For extension, copy, merge, cache tables, we haven't attached the
            # incoming edges yet. To do this we scan all tables again to modify
            # their next_table if their next_table point to such tables'
            # original tables.
            # This process requires cross-table information to decide the edges,
            # so we don't do it in node.prepare_optimizer_created_tables() where
            # only table-local information is needed

            reconnector = Reconnector(pipe)
            old_next_new_next = reconnector.get_next_opt_table_to_reconnect_for_root(pipe.root)
            if old_next_new_next:
                old_next, new_next = old_next_new_next
                pipe.remove_edge(pipe.root, old_next)
                pipe.add_edge(pipe.root, new_next)

            for node in pipe.normal_nodes + list(name_to_new_node.values()):
                old_next_to_new_next: Dict[
                    Table, OptTable
                ] = reconnector.get_next_opt_tables_to_reconnect_for_normal_nodes(node)
                for old_next, new_next in old_next_to_new_next.items():
                    node.replace_next_table(old_next.name, new_next.name)

            for node in name_to_removing_node.values():
                pipe.remove_node(node)
            for node in name_to_new_node.values():
                pipe.add_node(node)
            pipe.refresh_edges()

    @staticmethod
    def from_optimized_type_to_target_type(ir_graph: IrGraph):
        """Convert the optimized type to device target type"""
        for pipe in [ir_graph.get_pipe(p) for p in ir_graph.get_pipe_names()]:
            for node in pipe.normal_nodes:
                if node.optimized_type == OptimizedType.HW_STEERING:
                    node.target_type = DeviceTargetType.HW_STEERING
                elif node.optimized_type == OptimizedType.SW_STEERING:
                    node.target_type = DeviceTargetType.SW_STEERING
                elif node.optimized_type == OptimizedType.UNASSIGNED:
                    raise Exception("This table has not been optimized")
                else:
                    raise Exception(f"Node {node.name}'s optimized type has not been converted")

    @staticmethod
    def gen_table_mapping_dict(
        original_irg: IrGraph,
        target: MultiTargetBase,
    ) -> Dict[str, Any]:
        """
        Generates dict for bmv2 switch to map entry queries to impl'ed tables.
        """
        if config.GROUP_CACHE_ENABLED:
            return {}

        mapping = {
            "status": "running",
            "tables": {},
            "merge_tables": {},
            "cache_tables": {},
            "actions": {},
        }

        action_type_to_info_map: Dict[ActionType, ActionInfoMap] = {}
        original_actions: Set[Action] = set()
        for pipe_name in original_irg.get_pipe_names():
            pipe = original_irg.get_pipe(pipe_name)
            for table in pipe.tables:
                cxt_id = target.get_subtarget_cxt(table.target_type)
                table.update_mapping(cxt_id, mapping)
                for action, _ in table.action_iterator:
                    if isinstance(action, OptAction):
                        original_actions |= set(action.optimized_from)
                    else:
                        assert isinstance(action, Action)
                        original_actions |= {action}

        for action in original_actions:
            mapping["actions"][action.id] = {
                "name": action.name,
                "action_counters": [
                    {
                        "cxt": target.get_subtarget_cxt(dev_type),
                        "id": id,
                    }
                    for dev_type, id in action.post_opt_action_counters
                ],
            }

        return mapping

    @staticmethod
    def connect_extension_copy_tables(
        multi_target: MultiTargetBase,
        original_irg: IrGraph,
    ) -> Dict[DeviceTargetType, IrGraph]:
        """Create multiple IrGraph, each for one subtarget, and place tables based
        on their target, and insert ingress/egress tables if needed in each
        subtarget, and edit the edges accordingly. Then, we get a postsplit graph.
        """
        target_types = multi_target.subtarget_types
        target2irg: Dict[DeviceTargetType, IrGraph] = {}
        # create seperate graphs per target
        for target_type in target_types:
            target2irg[target_type] = deepcopy(original_irg)

        for pipeline_name in original_irg.get_pipe_names():
            original_irgpipe = original_irg.get_pipe(pipeline_name)
            if len(original_irgpipe) == 0:
                continue

            # make sure all nodes are known
            for node in original_irgpipe.normal_nodes:
                assert node.target_type in target_types, (
                    f"Node {node.name}, assigned to {node.target_type} " f"- target not in target list: {target_types}"
                )

            target_to_mitigation_sources = {}
            target_to_original_source_node = {}
            for target_type, target_graph in target2irg.items():
                # scan all edges, find ones that cross targets, and add mitigation table between.
                target_pipe = target_graph.get_pipe(pipeline_name)

                # cut the root -> init_table edge to make the init_table the first source
                original_source_node = target_pipe.get_init_table()
                target_pipe.remove_edge(target_pipe.root, original_source_node)
                target_to_original_source_node[target_type] = original_source_node

                # target2mitigation={k:[] for k in target2irg.keys()}
                target_to_mitigation_sources[target_type] = set()
                mitigation_edges = []
                for edge in target_pipe.normal_edges:
                    prev = edge[0]
                    suc = edge[1]
                    if (prev.target_type == target_type) and (suc.target_type != target_type):
                        mitigation_edges.append(edge)
                    if (prev.target_type != target_type) and (suc.target_type == target_type):
                        target_to_mitigation_sources[target_type].add(suc)
                print(f"Mitigation edges: {mitigation_edges}")

                for edge in mitigation_edges:
                    # add mitigation actions
                    JsonDeployer._add_egress_mitigation_table(
                        irg=target_graph,
                        multi_target=multi_target,
                        pipeline_name=pipeline_name,
                        prev_node=edge[0],
                        next_node=edge[1],
                    )

            # keep only assigned nodes
            for target_type, target_graph in target2irg.items():
                target_pipe = target_graph.get_pipe(pipeline_name)
                nodes_to_remove = list(filter(lambda n: n.target_type != target_type, target_pipe.normal_nodes))
                target_pipe.remove_nodes_from(nodes_to_remove)
                print(
                    f"Before insert ingress start table, pipeline {pipeline_name}, target {target_type} has nodes {[ node.name for node in target_pipe.normal_nodes]}"
                )

                # if not single source, add ingress next_table
                JsonDeployer._add_ingress_start_table(
                    irg=target_graph,
                    multi_target=multi_target,
                    pipeline_name=pipeline_name,
                    target_type=target_type,
                    original_source_node=target_to_original_source_node[target_type],
                    mitigation_sources=target_to_mitigation_sources[target_type],
                )

        for target_type, target_graph in target2irg.items():
            print(f"Target {target_type} after inserting ingress start table")
            JsonDeployer._check_splited_graph(target_graph)

        return target2irg

    def _for_each_table_in_running_json(
        self,
        target_id: int,
        target_irg: IrGraph,
        running_json_file_name: str,
        table_mapping: Dict[str, Any],
        func: Callable[[IrGraph, TableName, TableId, TableName, TableName], None],
    ):
        self._api.client.bm_mt_get_running_json(target_id, running_json_file_name)
        with open(running_json_file_name, "r") as f:
            json_str = f.read()
            postflexcore_json = json.loads(json_str)
            for pipeline_json in postflexcore_json["pipelines"]:
                for table in pipeline_json["tables"]:
                    table_name = table["name"]
                    table_id = table["id"]
                    suffix = f"${table_id}"
                    suffix_start = len(table_name) - len(suffix)

                    # special tables added during split (postopt)
                    if table_name[0] == "$":
                        continue

                    # tables that already exist in the pipeline before
                    # flexcore
                    if "$" not in table_name or table_name[-4:] == "$ext":
                        continue

                    assert suffix_start > 0 and suffix == table_name[suffix_start:], (
                        f"Will a post-flexcore table have a suffix that "
                        f"is not its table_id? Yes, here is an example: "
                        f"{table_name}"
                    )

                    preflexcore_name = table_name[:suffix_start]
                    if preflexcore_name[-4:] in ["$cpy", "$mrg", "$cch"]:
                        real_name = preflexcore_name[:-4]
                    else:
                        real_name = preflexcore_name
                    assert real_name in table_mapping, f"table {real_name} does not exist in " f"table_mapping"

                    func(target_irg, table_name, table_id, preflexcore_name, real_name)

    def invoke_flexcore_set_mapping(
        self,
        target: MultiTargetBase,
        target2irg: Dict[DeviceTargetType, IrGraph],
        mapping_dict: Dict[str, Any],
        round: int,
    ) -> bool:
        subtarget_types = target.subtarget_types
        target_id_to_changed = {target_id: False for target_id in range(0, len(target.subtarget_types))}
        new_json_template = r"{}_postsplit_postopt_{}.json"
        entry_json_template = r"{}_entry_population_{}.json"
        plan_template = r"{}_command_ProgPlanner_{}.txt"
        target_irg_to_inserted_table_preflexcore_names = {
            target2irg[subtarget_types[target_id]]: set() for target_id in range(len(subtarget_types))
        }
        target_irg_to_old_table_names: Dict[IrGraph, List[str]] = {
            target2irg[subtarget_types[target_id]]: [] for target_id in range(len(subtarget_types))
        }
        for target_id in range(len(subtarget_types)):
            target_irg = target2irg[subtarget_types[target_id]]
            old_json = f"{round}_postsplit_preopt_{target_id}.json"
            new_json = new_json_template.format(round, target_id)
            entry_json = entry_json_template.format(round, target_id)
            plan = plan_template.format(round, target_id)
            target_irg.export_p4cirjson(new_json)

            self._api.client.bm_mt_get_running_json(target_id, old_json)
            # Generate plan
            # there requires FlexCore-private under the same parent folder as
            # offloadoptimizer
            flexcore_script_path = os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "FlexCore-private", "src", "main.py"
            )
            cmd = f"python3 {flexcore_script_path} -use_action_ptr -p prog -b json -old {old_json} -new {new_json} -out ./ -entry {entry_json}"
            os.system(cmd)
            cmd = f"mv command_ProgPlanner.txt {plan}"
            os.system(cmd)
            print(f"Saved plan to: {plan}")

            # Two things:
            # 1) check if flexcore generates a plan changing the pipeline. Mark
            #    the `target_id_to_changed` flag,
            # 2) collect the inserted tables that later we need to populate
            #    entries on
            # 3) split the plan to two halves: one before `populate entry <file>`
            #    (excluded), and one after it (included). TODO: this step should
            #    be removed later after testing the splitted plan
            # 4) Collect the old tables' names from old_json. TODO: this step
            #    should be removed later after refactoring StandardServer to
            #    support better renaming

            # preflexcore means before runtime-bmv2's runtime_reconfig command
            inserted_table_preflexcore_names = target_irg_to_inserted_table_preflexcore_names[target_irg]

            with open(plan, "r") as f:
                first_line = True
                for line in f:
                    # This is for step 1)
                    if first_line:
                        first_line = False
                        if line.startswith("populate entry"):
                            logger.debug(f"No change is needed based on the flexcore result")
                            break
                        logger.debug(
                            f"Change is needed based on the flexcore result, because the first line is: {line}"
                        )
                        target_id_to_changed[target_id] = True

                    # This is for step 2)
                    words = line.split()
                    if len(words) >= 2 and (words[0], words[1]) == ("insert", "tabl"):
                        assert len(words) == 4, f"Unexpected insert tabl command format: {line}"
                        assert words[3][:4] == "new_", f"Unexpected inserted table name format: " f"{words[3]}"
                        inserted_table_preflexcore_names.add(words[3][4:])

            # Split the plan file into two TODO: remove this after testing
            if not target_id_to_changed[target_id]:
                continue
            with open(plan, "r") as f:
                if TESTING_SPLIT:
                    first_half_plan = (plan_template + ".first_half").format(round, target_id)
                    second_half_plan = (plan_template + ".second_half").format(round, target_id)

                    (first_half, populate_entry_line, second_half) = f.read().partition(
                        f"populate entry ./{entry_json}"
                    )
                    with open(first_half_plan, "w") as ff:
                        ff.write("start\n" + first_half)
                    with open(second_half_plan, "w") as fs:
                        fs.write(populate_entry_line + second_half + "\n" + "end")
                else:
                    first_half_plan = (plan_template + ".first_half").format(round, target_id)
                    second_half_plan = None
                    plan_content = f.read()
                    with open(first_half_plan, "w") as ff:
                        ff.write("start\n" + plan_content + "\n" + "end")

            # Read old tables' names from old_json
            with open(old_json, "r") as f:
                old_json_in_dict = json.load(f)
                for pipeline_json in old_json_in_dict["pipelines"]:
                    for table_json in pipeline_json["tables"]:
                        target_irg_to_old_table_names[target_irg].append(table_json["name"])

            # commit the first half of the plan (before `populate entry ./entry_ProgPlanner.txt`)
            new_json = new_json_template.format(round, target_id)
            self._api.client.bm_mt_runtime_reconfig(target_id, new_json, first_half_plan)

        # We still need to set mapping for now, because we need to change
        # 'status' back to 'running'
        # TODO: Probably want to avoid the following complicated processing on
        # other mapping key-value pairs
        # if not any(target_id_to_changed.values()):
        #     return False

        # Set mapping and entry_population file
        table_mapping = mapping_dict["tables"]
        merge_tables = mapping_dict["merge_tables"]
        cache_tables = mapping_dict["cache_tables"]
        PopulationEntryMapping = Dict[str, List[Any]]
        target_irg_to_population_entry_mapping: Dict[IrGraph, PopulationEntryMapping] = {
            target2irg[subtarget_types[target_id]]: {} for target_id in range(len(subtarget_types))
        }
        # TODO: The following mapping should be the same as the above one, but
        # since flexcore cannot detect the bmv2 generated table name, its
        # mapping is not what we want, so we separate the two and work around by
        # getting the wanted one based on old_jon
        target_irg_to_flexcore_gened_entry_mapping: Dict[IrGraph, PopulationEntryMapping] = {}
        for target_id in range(len(subtarget_types)):
            entry_population_file = entry_json_template.format(round, target_id)
            target_irg = target2irg[subtarget_types[target_id]]
            with open(entry_population_file, "r") as f:
                target_irg_to_flexcore_gened_entry_mapping[target_irg] = json.load(f)

        # 1) Define prepare_* functions for each table
        processed_preflexcore_table_names = set()

        def prepare_entry_population_file(
            target_irg: IrGraph,
            table_name: TableName,
            table_id: TableId,
            preflexcore_name: TableName,
            real_name: TableName,
        ) -> None:
            # Prepare entry_population
            postflexcore_table_name_to_population_entries = target_irg_to_population_entry_mapping[target_irg]
            inserted_table_preflexcore_names_from_flexcore = set(
                target_irg_to_flexcore_gened_entry_mapping[target_irg].keys()
            )
            inserted_table_preflexcore_names_from_command_parsing = target_irg_to_inserted_table_preflexcore_names[
                target_irg
            ]
            assert inserted_table_preflexcore_names_from_flexcore == (
                inserted_table_preflexcore_names_from_command_parsing
            ), (
                f"inserted_table_preflexcore_names_from_flexcore and "
                f"inserted_table_preflexcore_names_from_command_parsing "
                f"should be the same, but we got: \n"
                f"{inserted_table_preflexcore_names_from_flexcore}\n"
                f"{inserted_table_preflexcore_names_from_command_parsing}"
            )
            if (
                preflexcore_name in inserted_table_preflexcore_names_from_flexcore
                and table_name not in target_irg_to_old_table_names[target_irg]
            ):
                # assert preflexcore_name in inserted_table_preflexcore_names_from_command_parsing, (
                #     f"Table {table_name} is considered an inserted table by "
                #     f"flexcore, but not by JsonManager"
                # )
                assert preflexcore_name[-4:] != "$ext", (
                    f"We don't expect this code to be executed "
                    f"because extension table should be prepared "
                    f"at compile time and never changed at "
                    f"runtime by flexcore"
                )
                assert preflexcore_name not in (processed_preflexcore_table_names), (
                    f"Table with preflexcore table name {preflexcore_name} is "
                    f"being prepared with population entries second time"
                )
                processed_preflexcore_table_names.add(preflexcore_name)
                logger.debug(f"Prepare population entries for table {table_name}")

                postflexcore_table_name_to_population_entries[table_name] = [
                    entry._p4cir2json() for entry in target_irg.get_table(preflexcore_name).build_entries()
                ]
            else:
                logger.debug(
                    f"{preflexcore_name} is not prepared to have population "
                    f"entries because it is not considered an inserted table "
                    f"by flexcore"
                )

        def prepare_mapping(
            target_irg: IrGraph,
            table_name: TableName,
            table_id: TableId,
            preflexcore_name: TableName,
            real_name: TableName,
        ) -> None:
            # Prepare mapping
            if preflexcore_name[-4:] == "$cpy":
                assert "copied" in table_mapping[real_name], (
                    f"table {real_name} is considered " f"copied table by running json, but not by optimizer"
                )
                assert (
                    "renamed" not in table_mapping[real_name]["copied"]
                ), f"table {real_name}'s copy table renamed twice"
                table_mapping[real_name]["copied"]["renamed"] = table_name
            elif preflexcore_name[-4:] == "$ext":
                assert "migrated" in table_mapping[real_name], (
                    f"table {real_name} is considered " f"migrated table by running json, but not by optimizer"
                )
                assert (
                    "renamed" not in table_mapping[real_name]["migrated"]
                ), f"table {real_name}'s migrated table renamed twice"
                table_mapping[real_name]["migrated"]["renamed"] = table_name
            elif preflexcore_name[-4:] == "$mrg":
                assert "merged" in table_mapping[real_name], (
                    f"table {real_name} is considered " f"merged table by running json, but not by optimizer"
                )
                assert "renamed" not in merge_tables[preflexcore_name], (
                    f"table {real_name}'s merge table, {preflexcore_name}, " f"renamed twice"
                )
                merge_tables[preflexcore_name]["renamed"] = table_name
            elif preflexcore_name[-4:] == "$cch":
                assert "cached" in table_mapping[real_name], (
                    f"table {real_name} is considered " f"cached table by running json, but not by optimizer"
                )
                assert "renamed" not in cache_tables[preflexcore_name], (
                    f"table {real_name}'s cache table, {preflexcore_name}, " f"renamed twice"
                )
                cache_tables[preflexcore_name]["renamed"] = table_name
            else:
                assert "renamed" not in table_mapping[real_name], f"table {real_name} renamed twice"
                table_mapping[real_name]["renamed"] = table_name

        # 2) run the loop
        for target_id in range(0, len(subtarget_types)):
            target_irg = target2irg[subtarget_types[target_id]]
            post_first_half_file = f"{round}_postsplit_postopt_post_first_half_{target_id}.json"
            self._for_each_table_in_running_json(
                target_id,
                target_irg,
                post_first_half_file,
                table_mapping,
                prepare_entry_population_file,
            )

            # TODO: This if-condition should be moved earlier than calculating
            # the mapping, and the status-changing mapping should be easily
            # created before that.
            postflexcore_table_name_to_population_entries = target_irg_to_population_entry_mapping[target_irg]
            if target_id_to_changed[target_id]:
                entry_population_file = entry_json_template.format(round, target_id)
                with open(entry_population_file, "w") as f:
                    json.dump(
                        postflexcore_table_name_to_population_entries,
                        f,
                        indent=4,
                    )
                print(f"Saved entry population to: {entry_population_file}")

                if TESTING_SPLIT:
                    # commit the second half of the plan (after `populate entry <file>`)
                    second_half_plan = (plan_template + ".second_half").format(round, target_id)
                    new_json = new_json_template.format(round, target_id)
                    self._api.client.bm_mt_runtime_reconfig(target_id, new_json, second_half_plan)

            post_second_half_file = f"{round}_postsplit_postopt_post_second_half_{target_id}.json"
            self._for_each_table_in_running_json(
                target_id,
                target_irg,
                post_second_half_file,
                table_mapping,
                prepare_mapping,
            )

        # Set mapping
        # This must be done after the runtime_reconfig because we will unlock
        # the mapping status when set_mapping.
        with open("tmp.mapping_json", "w") as f:
            json.dump(mapping_dict, f, indent=4)
        print(f"Saved mapping to: tmp.mapping_json")
        self._api.do_set_mapping("tmp.mapping_json")

        return any(target_id_to_changed)

    @staticmethod
    def _get_node_unique_id(node: Union[GeneralTable, Condition]) -> int:
        """
        For mitigation table, gets unique id for both tables and conditions
        This is internal and used in metadata next table id and init table for next target.
        """
        unique_id = node.id
        if isinstance(node, Condition):
            unique_id += 1000  # TODO fix to be readable.
        return unique_id

    @staticmethod
    def _irg_gen_start_goto_actions(
        irg: IrGraph, pipeline_name, sources: List[IrNode], default_table_name: Optional[str]
    ) -> Tuple[Dict[str, Action], ConstEntries]:
        """for init table need unique action to map next tables to"""
        # TODO - convert to a switch condition instead of table
        new_actions = {}
        const_entries = []
        for idx, source in enumerate(sources):
            action_id = irg.next_action_id()
            action_name = f"init_goto_{pipeline_name}_{source.name}"
            action = {"name": action_name, "id": action_id, "runtime_data": [], "primitives": []}
            new_actions[source.name] = irg.add_action_from_json(action, Action)
            # assert(isinstance(source,general_table.GeneralTable)),f'TODO support uique ids between conditions and tables for mitiagtion {source}'
            const_entry = {
                "source_info": {},
                "match_key": [
                    {
                        "match_type": "exact",
                        "key": "{0:#0{1}x}".format(
                            JsonDeployer._get_node_unique_id(source), 10
                        ),  # ref https://stackoverflow.com/questions/12638408/decorating-hex-function-to-pad-zeros
                    }
                ],
                "action_entry": {"action_id": action_id, "action_data": []},
                "priority": idx,
            }
            const_entries.append(const_entry)

        # Add default action
        action_name = f"init_goto_{pipeline_name}_{default_table_name}"
        action = {"name": action_name, "id": irg.next_action_id(), "runtime_data": [], "primitives": []}
        new_actions[default_table_name] = irg.add_action_from_json(action, Action)
        return new_actions, const_entries

    @staticmethod
    def _add_flex_cond_count_tables(cond: Condition) -> List[IrNode]:
        added_nodes: List[IrNode] = []
        branch_metadatas = [  # branch, cond_branch_next, cond_branch_id
            ("true", cond.true_next, cond.id * 2),
            ("false", cond.false_next, cond.id * 2 + 1),
        ]
        for branch, cond_branch_next, cond_branch_id in branch_metadatas:
            action_json = {
                "name": "$flex_cond_count_action",
                "id": cond.irgraph.next_action_id(),
                "runtime_data": [],
                "primitives": [
                    {
                        "op": "count",
                        "parameters": [
                            {"type": "counter_array", "value": "$flex_cond_counter"},
                            {"type": "hexstr", "value": "{0:#0{1}x}".format(cond_branch_id, 8)},
                        ],
                        "source_info": {"filename": "Automated flex conditional counter"},
                    }
                ],
            }
            action = cond.irgraph.add_action_from_json(action_json, Action)
            flex_cond_table_json = {
                "name": f"$flex_cond_table_{cond.name}_{branch}",
                "id": cond.irgraph.next_table_id(),
                "source_info": {
                    "filename": f"Automated flex conditional table for {branch} branch of {cond.name}",
                },
                "key": [],
                "match_type": "exact",
                "type": "simple",
                "max_size": 1024,
                "with_counters": False,
                "support_timeout": False,
                "direct_meters": None,
                "action_ids": [action.id],
                "actions": [action.name],
                "base_default_next": cond_branch_next,
                "next_tables": {action.name: cond_branch_next},
                "default_entry": {
                    "action_id": action.id,
                    "action_const": True,
                    "action_data": [],
                    "action_entry_const": True,
                },
            }
            flex_cond_table = Table._p4cjson2ir(
                flex_cond_table_json,
                cond.irgraph,
            )
            flex_cond_table.target_type = cond.target_type
            added_nodes.append(flex_cond_table)
            cond.replace_next_table(cond_branch_next, flex_cond_table.name)
        return added_nodes

    @staticmethod
    def _add_flex_cond_counter(irgraph: IrGraph) -> None:
        max_id = -1
        for counter_array in irgraph._counter_arrays:
            assert "$flex_cond_counter" != counter_array["name"], f"flex conditional counter already exists in the json"
            max_id = max(max_id, counter_array["id"])
        num_cond_ids = -1
        for pipe in irgraph.pipelines:
            for cond in pipe.conditions:
                num_cond_ids = max(num_cond_ids, cond.id)
                added_nodes = JsonDeployer._add_flex_cond_count_tables(cond)
                pipe.add_nodes_from(added_nodes)
            pipe.refresh_edges()
        assert num_cond_ids < MAX_COND, "Too many conditionals for flex conditional counter"
        flex_cond_counter = {
            "id": max_id + 1,
            "is_direct": False,
            "name": "$flex_cond_counter",
            "size": MAX_COND,
            "source_info": {"filename": "Automated flex conditional counter"},
        }
        irgraph._counter_arrays.append(flex_cond_counter)

    @staticmethod
    def _irg_gen_end_goto_actions(irg: IrGraph, next_node: IrNode, next_target: str) -> Action:
        """
        Creates unique action per mitigation point (pipe end) - maps egress to next target, and sets next table in metadata
        TODO - review this implementation
        """
        action_name = f"mitigate_goto_{next_target}_{next_node.name}"
        new_action = {
            "name": action_name,
            "id": irg.next_action_id(),
            "runtime_data": [{"name": "next_target_cxt", "bitwidth": 8}, {"name": "next_table_id", "bitwidth": 16}],
            "primitives": [
                {
                    "op": "assign",
                    "parameters": [
                        {"type": "field", "value": ["standard_metadata", "flex_change_path"]},
                        {"type": "runtime_data", "value": 0},
                    ],
                    "source_info": {},
                },
                {
                    "op": "assign",
                    "parameters": [
                        {"type": "field", "value": ["standard_metadata", "flex_next_tab"]},
                        {"type": "runtime_data", "value": 1},
                    ],
                    "source_info": {},
                },
            ],
        }
        return irg.add_action_from_json(new_action, Action)

    @staticmethod
    def _add_egress_mitigation_table(
        irg: IrGraph, multi_target: MultiTargetBase, pipeline_name: str, prev_node: IrNode, next_node: IrNode
    ):
        """
        addes empty table with action to set meta for next table on other target, and egress from it.
        """
        irgpipe = irg.get_pipe(pipeline_name)
        next_target: DeviceTargetType = next_node.target_type
        next_target_id = multi_target.get_subtarget_cxt(next_target)
        default_action = JsonDeployer._irg_gen_end_goto_actions(
            irg=irg, next_node=next_node, next_target=multi_target.subtargets[next_target].name
        )
        # TODO mitigation to X can occure more than once -
        mitigation_table_name = f"$mitigate.target.{next_target}_{prev_node.name}_to_{next_node.name}"
        # assert(isinstance(next_node,general_table.GeneralTable)), 'for id uniquness, keeping only tables. otherwize need to uniquly define condition id and table id'
        next_node_id = JsonDeployer._get_node_unique_id(next_node)
        mitigation_table = Table(
            irgraph=irg,
            id=irg.next_table_id(),
            name=mitigation_table_name,
            keys=[],
            action_ids=[default_action.id],
            default_action_id=default_action.id,
            default_action_const=True,
            default_action_param=[next_target_id + 1, next_node_id],  # TODO - diffrenciate between table and condition
            # Note we reserve index 0 for no change_path so index starts from 1 - Kuofeng
            default_action_entry_const=True,
            max_size=1,
            next_table_selector=NextTableSelector(
                next_tables={
                    default_action.name: None,
                },
                base_default_next=None,
            ),
            # action_to_next_table={"default":(None,1)},
            entry_insertion_rate=0,
            target_type=prev_node.target_type,
            p4cjson_description={
                "match_type": "exact",
                "type": "simple",
                "with_counters": False,
                "support_timeout": False,
                "direct_meters": None,
                "key": [],
            },
        )
        if isinstance(prev_node, GeneralTable):
            prev_node.replace_next_table(next_node.name, mitigation_table_name)
            # prev_t_actions = []
            # for action,(next_table,_) in prev_node.action_to_next_table.items():
            #     if next_table == next_node.name:
            #         prev_t_actions.append(action)
            # assert(len(prev_t_actions)>0) ,f"next_table:{next_node.name} was not found in action to next table mapping: {prev_node.action_to_next_table} "
            # for pta in prev_t_actions:
            #     prev_node.action_to_next_table[pta] = (mitigation_table_name,1)
        elif isinstance(prev_node, Condition):
            if prev_node.false_next == next_node.name:
                prev_node.false_next = mitigation_table_name
            else:
                prev_node.true_next = mitigation_table_name
        else:
            raise TypeError("unknown Node type: f{prev_node}")

        irgpipe.add_node(mitigation_table)
        irgpipe.add_edge(prev_node, mitigation_table, probability=1)
        # irgpipe.add_edge(mitigation_table , irgpipe.sink, probability=1)

    @staticmethod
    def _add_ingress_start_conditions(irg: IrGraph, pipeline_name: str, target_name: str, original_source_node: IrNode):
        """
        Insert initial condition to the pipeline (replaces the add_ingress_start_table implementation)
        we use the nested ingrass condition to ease runtime-reopt implementation. mainly relevant for the BMV2 implementation
        """
        irgpipe = irg.get_pipe(pipeline_name)
        sources = irgpipe.get_sources()

        if len(sources) <= 1:
            return

    @staticmethod
    def _add_ingress_start_table(
        irg: IrGraph,
        multi_target: MultiTargetBase,
        pipeline_name: str,
        target_type: DeviceTargetType,
        original_source_node: IrNode,
        mitigation_sources: Set[IrNode],
    ):
        """
        Insert initial table to allow jumping to the currect stage at the pipe when mitigating between targets.
        we use the ingress table for HW freindly implementation - single lookup.
        """
        irgpipe = irg.get_pipe(pipeline_name)

        all_sources = set(mitigation_sources)
        if not isinstance(original_source_node, Sink) and original_source_node.target_type == target_type:
            all_sources.add(original_source_node)
            default_table_name = original_source_node.name
        else:
            # Kuofeng: Set default next to sink
            default_table_name = None

        if len(all_sources) < 2:
            if len(irgpipe) == 2:  # one root, one sink
                assert (
                    len(all_sources) == 0
                ), f"Should only have one root and one sink, but we have sources {all_sources} and nodes {irgpipe.nodes}"
                irgpipe.add_edge(irgpipe.root, irgpipe.sink)
            else:
                assert (
                    len(all_sources) == 1
                ), f"Should only have one root, one sink, one source, and other none-source nodes but we have sources {all_sources} and nodes {irgpipe.nodes}"
                irgpipe.add_edge(irgpipe.root, list(all_sources)[0])
            return
        const_entries = []
        action_list = []
        new_actions, const_entries = JsonDeployer._irg_gen_start_goto_actions(
            irg, pipeline_name, mitigation_sources, default_table_name
        )
        for k, a in new_actions.items():
            action_list.append(a)

        default_action = new_actions[default_table_name]
        # try:
        #     # non mitigated packet wont have metadata, so we need default action
        #     default_action = new_actions[original_source_node.name]
        # except KeyError:
        #     # default will hit only if packet was never mitigated.
        #     default_action = action_list[0]

        next_table_selector = NextTableSelector(
            next_tables={action.name: next_table for next_table, action in new_actions.items()},
            base_default_next=default_table_name,
        )
        # probability = 0.3 # TODO
        # action2nexttable = {a_name:(t,probability) for t,(_,_,a_name,_) in new_actions.items()}
        # action2nexttable["default"] = (default_table_name,probability)
        target_name = multi_target.subtargets[target_type].name
        init_table = Table(
            irgraph=irg,
            id=irg.next_table_id(),
            name=f"${target_name}_{pipeline_name}_start",
            keys=MatchKey._p4cjson2ir(
                [
                    {
                        "match_type": "exact",
                        "name": "standard_metadata.flex_next_tab",
                        "target": ["standard_metadata", "flex_next_tab"],
                        "mask": None,
                    }
                ]
            ),
            action_ids=[a.id for a in action_list],
            default_action_id=default_action.id,  # TODO - original graph source. Kuofeng: Change to the first action
            default_action_const=False,
            default_action_param=[],
            default_action_entry_const=False,
            max_size=len(mitigation_sources),
            next_table_selector=next_table_selector,
            # action_to_next_table=action2nexttable,
            entry_insertion_rate=0,
            target_type=target_type,
            const_entries=const_entries,
            p4cjson_description={
                "match_type": "exact",
                "type": "simple",
                "with_counters": False,
                "support_timeout": False,
                "direct_meters": None,
                "key": [  # TODO
                    {
                        "match_type": "exact",
                        "name": "standard_metadata.flex_next_tab:flex_next_tab",
                        "target": ["standard_metadata", "flex_next_tab"],
                        "mask": None,
                    }
                ],
            },
        )
        irgpipe.add_node(init_table)

        # TODO - evaluate probability - this is a really tricky one :)
        probability = 1.0 / len(all_sources)
        for s in all_sources:
            irgpipe.add_edge(init_table, s, probability=probability)
        irgpipe.add_edge(irgpipe.root, init_table)

    @staticmethod
    def _check_splited_graph(irg: IrGraph):
        """
        perform validation tests on the graph after splitting
        """
        # all nodes are assigned to same target
        for pipeline_name in irg.get_pipe_names():
            irgpipe = irg.get_pipe(pipeline_name)
            print(f"Nodes in pipeline {pipeline_name}: {[node.name for node in irgpipe.normal_nodes]}")
            targets = set(n.target_type for n in irgpipe.normal_nodes)
            assert (len(targets) <= 1) or (
                len(irgpipe) == 0
            ), f"in pipeline {pipeline_name}, More than one target in splitted graph: {targets}"
            irgpipe.validate()
