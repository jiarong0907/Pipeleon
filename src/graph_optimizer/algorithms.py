import itertools
from typing import Dict, List, Union
import pytest_is_running
import commons.config as config
from commons.constants import (
    ENABLE_MERGE_FILTER,
    OptimizeTarget,
    OptimizeMethod,
    OptimizedType,
)
from graph_optimizer.opt_utils import OptUtils
from graph_optimizer.json_manager import JsonManager, JsonPlanner, CopyManager
from graph_optimizer.options import *
from graph_optimizer.pipelet import Pipelet, PipeletGroup
from graph_optimizer.plan_evaluator import PlanEvaluator
from ir.condition import Condition
from commons.types import Bytes
from ir.irgraph_pipe import IrGraphPipe
from ir.ir_node import Root
from ir.match_key import MatchType
from ir.table import Table
from commons.base_logging import logger


class CommonOptimizer:
    @staticmethod
    def _compute_best_global_plan_dp(
        mavail: Bytes, iavail: int, optimize_target: OptimizeTarget, aggregated_options: List[List[AggregatedOption]]
    ) -> Optional[ProgramOption]:
        """Compute the best global combinations of PipeletOptions"""
        msize = (mavail - 1) // config.DP_MSTEP + 1
        isize = (iavail - 1) // config.DP_ISTEP + 1

        global_plan: List[List[ProgramOption]] = [
            [ProgramOption([], 0) for _ in range(isize + 1)] for _ in range(msize + 1)
        ]

        # Set the target gain
        if optimize_target == OptimizeTarget.LATENCY:
            gain_attr = "lgain"
        elif optimize_target == OptimizeTarget.THROUGHT:
            gain_attr = "tgain"
        else:
            raise Exception("Unrecognized optimization target!")

        for agg_idx in range(len(aggregated_options)):
            for m in reversed(range(0, msize + 1)):
                for i in reversed(range(0, isize + 1)):
                    for opt in aggregated_options[agg_idx]:
                        opt_mcost = (opt.mcost - 1) // config.DP_MSTEP + 1 if opt.mcost != 0 else 1
                        opt_icost = (opt.icost - 1) // config.DP_ISTEP + 1 if opt.icost != 0 else 1

                        if m - opt_mcost < 0 or i - opt_icost < 0:
                            continue
                        if m - opt_mcost > msize:
                            logger.warning(
                                f"mcost is negative. This could happen when the table size "
                                f"is too small, so the merge table could not reach the first "
                                f"step for the size change."
                            )
                            continue
                        if (
                            global_plan[m - opt_mcost][i - opt_icost].gain + opt.__getattribute__(gain_attr)
                            > global_plan[m][i].gain
                        ):
                            global_plan[m][i].gain = global_plan[m - opt_mcost][
                                i - opt_icost
                            ].gain + opt.__getattribute__(gain_attr)
                            if global_plan[m - opt_mcost][i - opt_icost].option is None:
                                global_plan[m][i].option = [opt]
                            else:
                                global_plan[m][i].option = global_plan[m - opt_mcost][i - opt_icost].option + [opt]

            # PipeletOptimizer._print_dp_arrays(mavail, iavail, global_plan)

        if global_plan[msize][isize].gain == 0:
            return None

        return global_plan[msize][isize]

    @staticmethod
    def _print_dp_arrays(mavail: Bytes, iavail: int, global_plan: List[List[ProgramOption]]) -> None:
        res = ""
        msize = (mavail - 1) // config.DP_MSTEP + 1
        isize = (iavail - 1) // config.DP_ISTEP + 1
        res = ""
        for m in range(msize):
            for i in range(isize):
                if global_plan[m][i] != None:
                    if global_plan[m][i].option != None:
                        res += "(" + str(global_plan[m][i].gain) + ", " + str(len(global_plan[m][i].option)) + "), "
                    else:
                        res += "(" + str(global_plan[m][i].gain) + ", 0), "
            res += "\n"
        print(res)


class PipeletOptimizer:
    def __init__(self, json_manager: JsonManager) -> None:
        self._json_manager = json_manager

    @staticmethod
    def reoptimize_dp(
        mavail: Bytes,
        iavail: int,
        optimize_method: List[OptimizeMethod],
        optimize_target: OptimizeTarget,
        pipelets: List[Pipelet],
        round: Optional[int] = None,
        log_path: Optional[str] = None,
    ) -> Optional[ProgramOption]:
        """Compute all possible options for each pipelet, and then compute
        the best global combinations of these pipelet options.
        """
        pipelet_options: List[List[PipeletOption]] = []

        logger.info("Computing all optimization options...")
        for pipelet in pipelets:
            options = PipeletOptimizer._compute_all_options(pipelet, optimize_method)
            pipelet_options.append(options)

        logger.info("Computing the global best using DP...")
        program_option = PipeletOptimizer._compute_best_global_plan_dp(
            mavail=mavail, iavail=iavail, optimize_target=optimize_target, pipelet_options=pipelet_options
        )
        if program_option != None and log_path != None:
            assert round != None, f"Cannot dump because round is None"
            program_option.log_dump(round, log_path)

        return program_option

    @staticmethod
    def _compute_best_global_plan_dp(
        mavail: Bytes, iavail: int, optimize_target: OptimizeTarget, pipelet_options: List[List[PipeletOption]]
    ) -> Optional[ProgramOption]:
        """Compute the best global combinations of PipeletOptions"""
        return CommonOptimizer._compute_best_global_plan_dp(mavail, iavail, optimize_target, pipelet_options)

    @staticmethod
    def _compute_all_options(pipelet: Pipelet, optimize_method: List[OptimizeMethod]) -> List[PipeletOption]:
        """Compute all possible valid combined optimizations for a pipelet"""
        res: List[PipeletOption] = []
        if OptimizeMethod.REORDER in optimize_method:
            reorder_plans = PipeletOptimizer._compute_reorder_plan(pipelet)
        else:
            reorder_plans = [ReorderOption(list(range(0, pipelet.length)))]

        for new_order in reorder_plans:
            # Create a copy to store the original pipelet
            pipelet_copy = CopyManager._copy_pipelet(pipelet)
            if OptimizeMethod.REORDER in optimize_method and new_order.new_table_pos != list(range(pipelet.length)):
                JsonPlanner.apply_reordering(pipelet_copy, new_order)

            all_opt_plans: List[CombinedOptionType] = []
            if OptimizeMethod.SOFTCOPY in optimize_method:
                softcopy_plans = PipeletOptimizer._compute_softcopy_plan(pipelet_copy)
                all_opt_plans += softcopy_plans

            if OptimizeMethod.SOFTMOVE in optimize_method:
                softmove_plans = PipeletOptimizer._compute_softmove_plan(pipelet_copy)
                all_opt_plans += softmove_plans

            if OptimizeMethod.MERGE in optimize_method:
                table_merge_plans = PipeletOptimizer._compute_table_merge_plan(pipelet_copy)
                all_opt_plans += table_merge_plans

            if OptimizeMethod.CACHE in optimize_method:
                cache_plans = PipeletOptimizer._compute_cache_plan(pipelet_copy)
                all_opt_plans += cache_plans

            if OptimizeMethod.REORDER in optimize_method and new_order.new_table_pos != list(
                range(len(new_order.new_table_pos))
            ):
                res.append(PipeletOptimizer.create_pipelet_option(pipelet, new_order, None))

            if len(all_opt_plans) == 0:
                continue

            # Validate the combined optimization plans
            count_options = 0
            count_valid_options = 0
            for length in range(1, len(all_opt_plans) + 1):
                for subset in itertools.combinations(all_opt_plans, length):
                    count_options += 1
                    if PipeletOptimizer._validate_combined_opts(pipelet, subset):
                        count_valid_options += 1
                        res.append(PipeletOptimizer.create_pipelet_option(pipelet, new_order, subset))
            logger.info(f"{count_options} options are found, {count_valid_options} are valid")
        return res

    @staticmethod
    def _validate_combined_opts(pipelet: Pipelet, combined_plans: List[CombinedOptionType]) -> bool:
        """Validate a combination of different optimizations.

        To simpilfy the optimization computation,
            - we assume each table can only be optimized by one technique
            - we support only one cache optimization for each pipelet
        """
        # reference count for each table
        ref_cnt = {i: 0 for i in range(pipelet.length)}
        # counter for number of cache options
        cache_counter = 0
        for plan in combined_plans:
            if (
                isinstance(plan, MergeOption)
                or isinstance(plan, CacheOption)
                or isinstance(plan, SoftcopyOption)
                or isinstance(plan, SoftmoveOption)
            ):
                s = plan.start_table_id
                for i in range(s, s + plan.length):
                    ref_cnt[i] += 1
                    if ref_cnt[i] > 1:
                        return False
                if isinstance(plan, CacheOption):
                    cache_counter += 1
                    if cache_counter > config.MAX_PER_PIPELET_CACHE:
                        return False
            else:
                raise Exception("Unrecognized optimization option!")

        return True

    @staticmethod
    def create_pipelet_option(
        pipelet: Pipelet, new_order: ReorderOption, combined_options: Optional[List[CombinedOptionType]]
    ) -> PipeletOption:
        pipelet_option = PipeletOption(pipelet, new_order, combined_options)
        PlanEvaluator._eval_pipelet_option(pipelet_option)
        return pipelet_option

    @staticmethod
    def _compute_reorder_plan(pipelet: Pipelet) -> List[ReorderOption]:
        """Compute the reorder plan for a given pipelet

        The output list has the following rule: table at location 0 will be
        reordered to location 1 if list[1] is 0
        """
        # all_plans:List[ReorderOption] = []
        # for order in itertools.permutations(list(range(0, pipelet.length))):
        #     all_plans.append(ReorderOption(list(order)))
        # return all_plans
        all_plans: List[ReorderOption] = []
        for order in list(OptUtils._topo_sort(pipelet.irgraph_pipe.ir_graph, pipelet)):
            all_plans.append(ReorderOption(order))
        return all_plans

    @staticmethod
    def _is_softmove_beneficial(irgraph_pipe: IrGraphPipe, table: Table) -> bool:
        """Determine whether a table should be optimized by Softmove.
        A table should be moved if and only if all its predecessors are in software.
        TODO: This only considers copy after a table. Specifically, if there is a semi-supported
        table at the end of the pipeline, and there is a table before it in the same pipelet, that
        table will not be considered for softcopy
        """
        predecessors = list(irgraph_pipe.predecessors(table))
        for p in predecessors:
            if isinstance(p, Root):
                continue
            elif isinstance(p, Condition):
                return False
            elif isinstance(p, Table):
                if p.optimized_type != OptimizedType.SW_STEERING:
                    return False
            else:
                raise Exception(f"Unexpected instance type {type(p)} for node in irgraph_pipe.")
        return True

    @staticmethod
    def _is_softcopy_beneficial(irgraph_pipe: IrGraphPipe, table: Table) -> bool:
        """Determine whether a table should be optimized by Softcopy.
        A table should be copied if and only if part of its predecessors are in software
        and the other part are in hardawre.
        TODO: This only considers copy after a table. Specifically, if there is a semi-supported
        table at the end of the pipeline, and there is a table before it in the same pipelet, that
        table will not be considered for softcopy
        """
        predecessors = list(irgraph_pipe.predecessors(table))
        has_sw_predecessor = False
        has_hw_predecessor = False

        for p in predecessors:
            if isinstance(p, Root):
                continue
            elif isinstance(p, Condition):
                has_hw_predecessor = True
            elif isinstance(p, Table):
                if p.optimized_type == OptimizedType.SW_STEERING:
                    has_sw_predecessor = True
                if p.optimized_type == OptimizedType.HW_STEERING:
                    has_hw_predecessor = True
                if p.optimized_type == OptimizedType.SEMI_SUPPORTED:
                    has_sw_predecessor = True
                    has_hw_predecessor = True
            else:
                raise Exception(f"Unexpected instance type {type(p)} for node in irgraph_pipe.")
            if has_hw_predecessor and has_sw_predecessor:
                return True
        return False

    @staticmethod
    def _compute_soft_copy_move_plan(pipelet: Pipelet, move: bool) -> List[Union[SoftcopyOption, SoftmoveOption]]:
        # collect the starting subtargets (as number) for all tables
        # in the pipelet
        optimized_types = pipelet.table_optimized_types
        tables = pipelet.tables
        # We identify all segments with continuous zeros that are enclosed by
        # two non-zero numbers. These segments are candidates for us to decide
        # whether to create a soft copy.
        all_plans: List[Union[SoftcopyOption, SoftmoveOption]] = []

        # We do not do softcopy or softmove if there is only one table in this pipelet
        # Because the boundary of this pipelet is if-else branch, which cannot be put
        # into software. Moving/copying a table to software has no benefit.
        if len(tables) == 1:
            return all_plans

        start_id, length = -1, 0
        for i in range(len(optimized_types)):
            if optimized_types[i] == OptimizedType.HW_STEERING and start_id == -1:
                start_id, length = i, 1
                continue
            if optimized_types[i] == OptimizedType.HW_STEERING:
                length += 1
            elif length > 0:
                if move and PipeletOptimizer._is_softmove_beneficial(pipelet.irgraph_pipe, tables[start_id]):
                    all_plans.append(SoftmoveOption(start_id, length))
                elif not move and PipeletOptimizer._is_softcopy_beneficial(pipelet.irgraph_pipe, tables[start_id]):
                    all_plans.append(SoftcopyOption(start_id, length))
                start_id, length = -1, 0
        if length > 0:
            if move and PipeletOptimizer._is_softmove_beneficial(pipelet.irgraph_pipe, tables[start_id]):
                all_plans.append(SoftmoveOption(start_id, length))
            elif not move and PipeletOptimizer._is_softcopy_beneficial(pipelet.irgraph_pipe, tables[start_id]):
                all_plans.append(SoftcopyOption(start_id, length))
        return all_plans

    @staticmethod
    def _compute_softcopy_plan(pipelet: Pipelet) -> List[SoftcopyOption]:
        """Compute the softcopy plan for a given pipelet

        The output is a list of softcopy options that has the following rules:
            - each option has two numbers [start_id, length]
            - e.g., option [0, 3] means copy table 1 to table 3 to ARM
        """
        plans = PipeletOptimizer._compute_soft_copy_move_plan(pipelet=pipelet, move=False)
        for p in plans:
            assert isinstance(p, SoftcopyOption)
        return plans

    @staticmethod
    def _compute_softmove_plan(pipelet: Pipelet) -> List[SoftmoveOption]:
        """Compute the softmove plan for a given pipelet

        The output is a list of softmove options that has the following rules:
            - each option has two numbers [start_id, length]
            - e.g., option [0, 3] means copy table 1 to table 3 to ARM

        The difference between softcopy and softmove is that softmove will
        keep the table only in software while softcopy creates a copy of the table
        in software. Thus, in softcopy, the original is still in hardware, but
        softmove will delete the table in hardware.
        """
        plans = PipeletOptimizer._compute_soft_copy_move_plan(pipelet=pipelet, move=True)
        for p in plans:
            assert isinstance(p, SoftmoveOption)
        return plans

    @staticmethod
    def _compute_table_merge_plan(pipelet: Pipelet) -> List[MergeOption]:
        """Compute the table merge plan for a given pipelet

        The output is 2-d array that has the following rules:
            - each entry in the array is a possible merge choice
            - each entry has two numbers [start_id, length]
            - e.g., entry [0, 2] means merge table 1 and table 2
            - we merge only tables entirely in ASICs
            - length is restricted to 2 current
        """
        # collect all tables in the pipelet
        tables = pipelet.tables

        # for every two consecutive tables, we consider whether they can be merged
        # rules to merge two tables:
        #   - both must be in ASICs
        #   - the table size is small and relatively static (low insertion rate)
        plan: List[MergeOption] = []
        for i in range(0, len(tables) - 1):
            table_i = tables[i]
            table_j = tables[i + 1]

            # We only consider merging tables when there are both completely in ASICs
            if (
                table_i.optimized_type != OptimizedType.HW_STEERING
                or table_j.optimized_type != OptimizedType.HW_STEERING
            ):
                continue

            # if one table has high insertion rate or table size is very large
            # table merge will amplify the insertion rate and memory footprint,
            # so we first filter out such tables.
            assert (
                table_i.entry_insertion_rate != None
                and table_j.entry_insertion_rate != None
                and table_i.current_size != None
                and table_j.current_size != None
            ), (
                f"The entry_insertion_rate or current_size is not set for"
                f"table_name={table_i.name} and table_name={table_j.name}"
            )
            # TODO: this is disabled for getting samples for ml algorithms
            if ENABLE_MERGE_FILTER:
                if (
                    table_i.entry_insertion_rate > config.MERGE_INSERT_RATE_THRESHOLD
                    or table_j.entry_insertion_rate > config.MERGE_INSERT_RATE_THRESHOLD
                    or table_i.current_size > config.MERGE_TABLE_SIZE_THRESHOLD
                    or table_j.current_size > config.MERGE_TABLE_SIZE_THRESHOLD
                ):
                    continue
                # dependency check
                if not OptUtils._can_merge(pipelet.irgraph_pipe.ir_graph, table_i, table_j):
                    continue
            else:
                logger.warning(
                    f"Merge filter is disabled. All tables will be considered for merging. "
                    f"This should only be used for ML test."
                )

            # we add the feasible merge candidates to the list
            # we support merging only two consecutive tables currently
            plan.append(MergeOption(i, 2))

        return plan

    @staticmethod
    def _compute_cache_plan(pipelet: Pipelet) -> List[CacheOption]:
        """Compute the cache plan for a given pipelet

        The output is a cache option that has the following rules:
            - each option has two numbers [start_id, length]
            - e.g., option [0, 3] means cache table 1 to table 3
            - we cache only consecutive tables entirely in ASICs
            - Every pipelet has only one cache, enforced in plan validation
        """
        # collect all consecutive tables in the pipelet
        next_start = pipelet.root

        consec_tables = []
        cur_consec_tables = []
        for i in range(0, pipelet.length):
            assert isinstance(next_start, Table), (
                f"All nodes in a pipelet should be a Table, but we got"
                f" a {next_start.__class__.__name__} node: {next_start}"
            )

            # the cur_consec_table is cut by a table not in ASICs
            if next_start.optimized_type != OptimizedType.HW_STEERING:
                if len(cur_consec_tables) > 0:
                    consec_tables.append(cur_consec_tables)
                    cur_consec_tables = []
            else:
                cur_consec_tables.append(i)

            successors = list(pipelet.irgraph_pipe.successors(next_start))
            assert len(successors) == 1, (
                f"Node in a pipelet should have a single successor, but node "
                f"{next_start} has multiple: {successors}"
            )
            next_start = successors[0]
        if len(cur_consec_tables) > 0:
            consec_tables.append(cur_consec_tables)
        # compute all possible cache plans, which are the collection of all consecutive
        # tables with different lengths.
        all_possible_plans = []
        for consec_table in consec_tables:
            # for each starting point
            for start in range(0, len(consec_table)):
                # consider all possible lengths
                for length in range(1, len(consec_table) + 1):
                    if start + length <= len(consec_table):
                        # cache for single exact table is meaningless
                        if length == 1 and pipelet.tables[start].match_type == MatchType.EXACT:
                            continue
                        # check whether the plan is valid
                        if not OptUtils._can_cache(
                            pipelet.irgraph_pipe.ir_graph,
                            [pipelet.tables[i] for i in range(consec_table[start], consec_table[start] + length)],
                        ):
                            continue
                        all_possible_plans.append(CacheOption(consec_table[start], length))

        # TODO: We can reduce the search space here by checking whether the table is very dynamic
        # return the best plan
        return list(all_possible_plans)


class PipeletGroupOptimizer:
    def __init__(self, json_manager: JsonManager) -> None:
        self._json_manager = json_manager

    @staticmethod
    def reoptimize_dp(
        mavail: Bytes,
        iavail: int,
        optimize_method: List[OptimizeMethod],
        optimize_target: OptimizeTarget,
        pipelet_groups: List[PipeletGroup],
    ) -> Optional[ProgramOption]:
        """Compute all possible options for each pipelet, and then compute
        the best global combinations of these pipelet options.
        """
        pipe_grp_options: List[List[PipeletGroupOption]] = []

        for pipe_grp in pipelet_groups:
            options = PipeletGroupOptimizer._compute_all_options(pipe_grp, optimize_method)
            if len(options) == 0:
                continue
            pipe_grp_options.append(options)

        return PipeletGroupOptimizer._compute_best_global_plan_dp(
            mavail=mavail, iavail=iavail, optimize_target=optimize_target, pipelet_group_options=pipe_grp_options
        )

    @staticmethod
    def _check_need_group_cache(pipe_grp: PipeletGroup) -> bool:
        if pytest_is_running.is_running():
            return True

        # The group cache option is meaningful when
        # (1) there more than one tables
        # (2) only one table but not exact
        # in both cases, there should be some pipelet options.
        table_count = 0
        has_non_exact_table = False
        for pipelet in pipe_grp.pipelets:
            for table in pipelet.tables:
                table_count += 1
                if table.match_type != MatchType.EXACT:
                    return True
        return table_count > 1

    @staticmethod
    def _compute_all_options(pipe_grp: PipeletGroup, optimize_method: List[OptimizeMethod]) -> List[PipeletGroupOption]:
        """Compute all possible valid combined optimizations for a PipeletGroup"""
        res: List[PipeletGroupOption] = []
        list_pipelet_options: List[List[PipeletOption]] = []
        for pipelet in pipe_grp.pipelets:
            pipelet_options = PipeletOptimizer._compute_all_options(pipelet, optimize_method)
            pipelet_options.append(None)
            list_pipelet_options.append(pipelet_options)

        # itertools.product(*[[1,2],[3,4],[5,6]]) ==> [(1, 3, 5), (1, 3, 6),...
        cross_products = itertools.product(*list_pipelet_options)
        for cro_pro in cross_products:
            pruned_cro_pro = [cp for cp in cro_pro if cp is not None]
            if len(pruned_cro_pro) == 0:
                continue
            group_option = PipeletGroupOption(
                pipelet_group=pipe_grp, pipelet_options=pruned_cro_pro, group_options=None
            )
            PlanEvaluator._eval_pipelet_group_option(group_option)
            res.append(group_option)

        # TODO: Does not support group merge now, because it is hard to
        # produce table entries even for conditions like if (hdr.tcp.srcPort==80),
        # we need to generate entries for negation.

        # group_merge_option = PipeletGroupOption(
        #     pipelet_group=pipe_grp,
        #     pipelet_options = None,
        #     group_options = [
        #         GroupMergeOption(
        #             root = pipe_grp.root,
        #             sink = pipe_grp.sink,
        #             size = pipe_grp.size,
        #             pipelets = pipe_grp.pipelets
        #         )
        #     ]
        # )
        # PlanEvaluator._eval_pipelet_group_option(group_merge_option)
        # res.append(group_merge_option)

        # The group cache option is meaningful when
        # (1) there more than one tables
        # (2) only one table but not exact
        # in both cases, there should be some pipelet options.
        if PipeletGroupOptimizer._check_need_group_cache(pipe_grp):
            group_cache_option = PipeletGroupOption(
                pipelet_group=pipe_grp,
                pipelet_options=None,
                group_options=[
                    GroupCacheOption(
                        root=pipe_grp.root, sink=pipe_grp.sink, size=pipe_grp.size, pipelets=pipe_grp.pipelets
                    )
                ],
            )
            PlanEvaluator._eval_pipelet_group_option(group_cache_option)
            res.append(group_cache_option)

        return res

    @staticmethod
    def _compute_best_global_plan_dp(
        mavail: Bytes,
        iavail: int,
        optimize_target: OptimizeTarget,
        pipelet_group_options: List[List[PipeletGroupOption]],
    ) -> Optional[ProgramOption]:
        """Compute the best global combinations of PipeletOptions"""
        return CommonOptimizer._compute_best_global_plan_dp(mavail, iavail, optimize_target, pipelet_group_options)
