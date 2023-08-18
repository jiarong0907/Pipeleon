from copy import deepcopy
from typing import Any, Dict, Tuple

from graph_optimizer.json_manager import JsonManager, JsonPlanner
from graph_optimizer.options import *
from graph_optimizer.runtime_states import CondCountProfile, TableCountProfile, RuntimeStates
from graph_optimizer.algorithms import PipeletGroupOptimizer, PipeletOptimizer
from commons.constants import DeviceTargetType, OptimizeMethod, OptimizeTarget
import commons.config as config
from commons.types import Bytes, MicroSec
from ir.irgraph import IrGraph
from commons.base_logging import logger
from ir.table_entry import TableEntry


class Optimizer:
    def __init__(self, api, sampling_period_us: MicroSec, optimization_log_path: Optional[str] = None):
        if api:
            self._json_manager: JsonManager = JsonManager(api)
        else:
            self._json_manager = None
        self._optimization_log_path = optimization_log_path
        self._sampling_period_us: MicroSec = sampling_period_us
        self._round: int = 0
        self._last_round_graph = None
        self._last_round_topk = None
        self._valid_opt_times = 0

    def do_one_time_optimize(
        self,
        input_json_path: str,
    ) -> Tuple[Dict[DeviceTargetType, IrGraph], Dict[str, Any]]:
        """
        Splits IrGraph pipes between targets
        """
        presplit_irg, target = JsonManager.retrieve_presplit(input_json_path)
        JsonManager.compile_time_json_planning(presplit_irg)
        # Runtime json planning needs the optimizer, which labels the IR
        if self._json_manager:  # if json_manager is not set => comopile-time optimization
            presplit_preopt_irg = deepcopy(presplit_irg)
            # self.reoptimize(presplit_irg)
            changed = self.reoptimize_pipelet(presplit_irg)
            if changed:
                self._last_round_graph = deepcopy(presplit_irg)
            elif self._last_round_graph != None:
                presplit_irg = deepcopy(self._last_round_graph)

            # self.reoptimize_pipelet_group(presplit_irg, OptimizeTarget.LATENCY)

        mapping_dict = JsonManager.from_plan_labeling_to_single_json(
            target,
            presplit_irg,
        )
        target2irg = JsonManager.from_single_json_to_multitarget_jsons(target, presplit_irg)
        if self._json_manager:
            self._json_manager.deploy_new_multitarget_jsons(
                target,
                target2irg,
                mapping_dict,
                presplit_preopt_irg,
                input_json_path,
                self._round,
            )
        return target2irg, mapping_dict

    @property
    def json_manager(self) -> JsonManager:
        return self._json_manager

    def _update_pipeline_stats(self, irg: IrGraph, runtime_states: RuntimeStates):
        table_counters = runtime_states.table_to_counts
        cond_counters = runtime_states.cond_to_counts
        table_sizes = runtime_states.table_to_size
        mapping_dict = runtime_states.mapping_dict
        entry_insertion_rates = {
            table_name: count * 1000000 / self._sampling_period_us
            for (table_name, count) in runtime_states.table_to_entry_insertion_count.items()
        }

        for irg_pipe in irg.pipelines:
            # Initialize probability for each table in the pipelines
            for table in irg_pipe.tables:
                counter: TableCountProfile = table_counters[table.name]
                action_name_to_count = {
                    metadata.action_name: counter.counts[action_id]
                    for action_id, metadata in counter.action_meta.items()
                }
                table.update_prob_with_counts(action_name_to_count)

            # Initialize probability for each conditional in the pipelines
            for cond in irg_pipe.conditions:
                counter: CondCountProfile = cond_counters[cond.name]
                cond.update_prob_with_counts(counter.counts)

            irg_pipe.refresh_edges()

        ingress_graph = irg.get_pipe("ingress")
        # setup the table size and entry insertion rate for each table
        for table in ingress_graph.tables:
            table.current_size = table_sizes[table.name]
            table.entry_insertion_rate = int(entry_insertion_rates[table.name])
            table.entries = [
                TableEntry._p4cjson2ir(entry_json) for entry_json in mapping_dict["tables"][table.name]["entries"]
            ]

    def reoptimize(self, irg: IrGraph):
        """One iteration of optimization

        This can include many different optimization techniques, such as
        reordering, merging, caching, etc.
        The optimization is done on the input irg directly.
        """
        round = self._round
        self._round += 1
        json_manager = self._json_manager
        irg.export_p4cirjson(f"{round}_presplit_preopt.json")
        runtime_states = json_manager.retrieve_runtime_states(
            f"{round}_presplit_preopt.json",
            f"{round}_mapping.json",
        )
        self._update_pipeline_stats(irg, runtime_states)
        # TODO: test on arm_json for now
        ingress_graph = irg.get_pipe("ingress")
        pipelets = JsonPlanner.get_pipelets(ingress_graph)

        # TODO: For now, I use reordering as a demo. Need to add the others
        for pipelet in pipelets:
            # option_cls = SoftcopyOption
            option_cls = CacheOption
            # option_cls = MergeOption
            for plan in JsonPlanner.get_all_plans(pipelet, option_cls):
                print("====================")
                print(f"Plan: {plan}")
                result = JsonManager.try_segment_opt(pipelet, plan)
                print(result)
            JsonPlanner.run_opt_segment(pipelet, runtime_states.table_to_counts, option_cls)

        # api.client.bm_mt_runtime_reconfig(0, args.json_file, args.plan_file)
        # load_json_config(json_path = args.json_file+".new") # TODO(Kuofeng): For now, assuming client is on switch and current path is at the build folder

        # api.do_table_dump(args.table_name)

        # api.do_get_running_json("tmp2.json")

    def check_valid_runtime_stats(self, runtime_stats) -> bool:
        total_counter = 0
        threshold = 5
        valid_counter = 0

        for table_name in runtime_stats.table_to_counts.keys():
            profile = runtime_stats.table_to_counts[table_name]
            for action_id in profile.counts.keys():
                counter = profile.counts[action_id]
                total_counter += 1
                if counter >= threshold:
                    valid_counter += 1
        # for cond_name in runtime_stats.cond_to_counts.keys():
        #     counter = runtime_stats.cond_to_counts[cond_name].counts
        #     total_counter += 2
        #     if counter['true'] > threshold:
        #         valid_counter += 1
        #     if counter['false'] > threshold:
        #         valid_counter += 1

        return valid_counter >= 3

    def reoptimize_pipelet(self, irg: IrGraph) -> bool:
        """Call the real dp algorithm to compute the optimization plans"""
        round = self._round
        self._round += 1
        json_manager = self._json_manager
        irg.export_p4cirjson(f"{round}_presplit_preopt.json")
        runtime_states = json_manager.retrieve_runtime_states(
            f"{round}_presplit_preopt.json",
            f"{round}_mapping.json",
        )

        logger.info(runtime_states.get_counter_info())

        if not self.check_valid_runtime_stats(runtime_states):
            logger.info("Most counters are 0s. Do nothing!")
            return False

        self._update_pipeline_stats(irg, runtime_states)

        # TODO: test on arm_json for now
        ingress_graph = irg.get_pipe("ingress")

        tables = list(ingress_graph.tables)
        conds = list(ingress_graph.conditions)

        for c in conds:
            logger.info(f"cond_name: {c.name}, true_prob: {c.true_probability}, false_prob: {c.false_probability}")

        for t in tables:
            logger.info(f"tab_name: {t.name}")
            for a, p in t.action_iterator:
                logger.info(f"act_name:{a.name}, prob:{p}")

        pipelets = JsonPlanner.get_pipelets(ingress_graph)
        topk_pipelets = JsonPlanner.get_topk_pipelets(pipelets, config.FLEX_CONTROL_TOPK, OptimizeTarget.LATENCY)

        logger.info(f"Last round topk: {self._last_round_topk}")
        logger.info(f"This round topk: {[p.root.name for p in topk_pipelets]}")

        if self._last_round_topk == None:
            self._last_round_topk = [p.root.name for p in topk_pipelets]
        else:
            if self._last_round_topk == [p.root.name for p in topk_pipelets]:
                return False

            # for tp in topk_pipelets:
            #     if tp.root.name in self._last_round_topk:
            #         self._last_round_topk = [p.root.name for p in topk_pipelets]
            #         return False
        self._last_round_topk = [p.root.name for p in topk_pipelets]

        # To work around the counter bug; otherwise a wrong optimization will be performed at the end
        if self._valid_opt_times >= 3:
            return False

        logger.info("topk pipelet")
        logger.info([f"{p.root.name}" for p in topk_pipelets])
        # enabled_optimizations = [OptimizeMethod.REORDER]
        enabled_optimizations = [
            OptimizeMethod.REORDER,
            # OptimizeMethod.SOFTCOPY,
            # OptimizeMethod.SOFTMOVE,
            OptimizeMethod.CACHE,
            # OptimizeMethod.MERGE,
        ]
        assert self._json_manager != None, f"Cannot run the optimizer without a json manager"
        dp_optimizer = PipeletOptimizer(self._json_manager)

        mavail = runtime_states.total_memory
        iavail = runtime_states.total_entry_insertion_bandwidth

        # The current memory and insertion bandwidth is too larger
        # Will cause the dp algorithm to take long time to complete
        # mavail = min(1000, mavail)
        # iavail = min(1000, iavail)

        prog_option: Optional[ProgramOption] = dp_optimizer.reoptimize_dp(
            mavail=mavail,
            iavail=iavail,
            optimize_method=enabled_optimizations,
            optimize_target=OptimizeTarget.LATENCY,
            pipelets=topk_pipelets,
            round=round,
            log_path=self._optimization_log_path,
        )
        if prog_option == None:
            logger.info("No optimization plan available. Do nothing")
            return False

        assert len(prog_option.option) > 0, f"Should get at least one pipelet option"
        logger.info(f"Found {len(prog_option.option)} optimizations, " f"total gain is {prog_option.gain}")

        for pipelet_option in prog_option.option:
            assert isinstance(
                pipelet_option, PipeletOption
            ), f"The option inside ProgramOption is not PipeletOption for pipelet optimization"
            pipelet = pipelet_option.pipelet
            new_order = pipelet_option.new_order
            JsonPlanner.apply_reordering(pipelet, new_order)
            if pipelet_option.combined_options == None:
                continue
            for comb_option in pipelet_option.combined_options:
                JsonPlanner.apply_segment_opt(pipelet, comb_option)
        self._valid_opt_times += 1
        return True

    def reoptimize_pipelet_group(self, irg: IrGraph, optimize_target: OptimizeTarget):
        """Call the topk dp algorithm to compute the optimization plans"""
        round = self._round
        self._round += 1
        json_manager = self._json_manager
        irg.export_p4cirjson(f"{round}_presplit_preopt.json")
        runtime_states = json_manager.retrieve_runtime_states(
            f"{round}_presplit_preopt.json",
            f"{round}_mapping.json",
        )
        self._update_pipeline_stats(irg, runtime_states)

        ingress_graph = irg.get_pipe("ingress")
        pipelets = JsonPlanner.get_pipelets(ingress_graph)
        topk_pipelets = JsonPlanner.get_topk_pipelets(pipelets, config.FLEX_CONTROL_TOPK, optimize_target)

        pipelet_groups = JsonPlanner.get_pipelet_groups(
            irgraph_pipe=ingress_graph, topk_pipelets=topk_pipelets, all_pipelets=pipelets
        )

        # enabled_optimizations = [OptimizeMethod.REORDER]
        enabled_optimizations = [OptimizeMethod.SOFTCOPY]
        assert self._json_manager != None, f"Cannot run the optimizer without a json manager"
        dp_optimizer = PipeletGroupOptimizer(self._json_manager)

        mavail = runtime_states.total_memory
        iavail = runtime_states.total_entry_insertion_bandwidth

        # The current memory and insertion bandwidth is too larger
        # Will cause the dp algorithm to take long time to complete
        mavail = min(1000, mavail)
        iavail = min(1000, iavail)

        prog_option: Optional[ProgramOption] = dp_optimizer.reoptimize_dp(
            mavail=mavail,
            iavail=iavail,
            optimize_method=enabled_optimizations,
            optimize_target=OptimizeTarget.LATENCY,
            pipelet_groups=pipelet_groups,
        )
        if prog_option == None:
            logger.info("No optimization plan available. Do nothing")
            return

        assert len(prog_option.option) > 0, f"Should get at least one pipelet option"
        logger.info(f"Found {len(prog_option.option)} optimizations, " f"total gain is {prog_option.gain}")

        for agg_option in prog_option.option:
            assert isinstance(agg_option, PipeletGroupOption), (
                f"The option inside ProgramOption is not PipeletGroupOption " f"for pipelet group optimization."
            )
            if agg_option.pipelet_options is not None:
                assert agg_option.group_options is None, f"Both pipelet options and group options are not None"
                for pipelet_option in agg_option.pipelet_options:
                    pipelet = pipelet_option.pipelet
                    new_order = pipelet_option.new_order
                    JsonPlanner.apply_reordering(pipelet, new_order)
                    if pipelet_option.combined_options == None:
                        continue
                    for comb_option in pipelet_option.combined_options:
                        JsonPlanner.apply_segment_opt(pipelet, comb_option)
            else:
                assert agg_option.group_options is not None, f"Both pipelet options and group options are None"
                grp_options = agg_option.group_options
                assert len(grp_options) == 1, (
                    f"The group option should have a GroupMergeOption, " f"but got {type(grp_options[0])}"
                )

                original_pipe_grp = agg_option.pipelet_group
                pipe_grp_copy = deepcopy(original_pipe_grp)
                if isinstance(grp_options[0], GroupMergeOption):
                    JsonPlanner.apply_group_merge(pipe_grp_copy, grp_options[0])
                elif isinstance(grp_options[0], GroupCacheOption):
                    JsonPlanner.apply_group_cache(pipe_grp_copy)
                else:
                    raise TypeError(f"Unrecognized group option type {type(grp_options[0])}")
