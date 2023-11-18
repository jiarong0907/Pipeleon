# Pipeleon User Guide

## Input

The input to Pipeleon includes a P4 json file generated by [P4C](https://github.com/p4lang/p4c) and a runtime profile `RuntimeStates`.

The [testdata](./tests/testdata/) folder provides many example P4 programs and their json files.

The program definition of `RuntimeStates` is [here](src/graph_optimizer/runtime_states.py#34).
In practical usage, this profile should be generated by Pipeleon runtime using data collected from SmartNICs.
For easy simulation, we provide a function [gen_runtime_stats](tests/utils.py#382) to synthesize it.
It is usually used together with `mock_import` to simulate the process of retrieving runtime profiles.

```
import mock_import
from runtime_CLI import RuntimeAPI

@patch("graph_optimizer.json_manager.JsonManager.retrieve_runtime_states")
def func_name(param_1, param_2, ..., retrieve_runtime_states):
    ...
    retrieve_runtime_states.return_value = TestUtils.gen_runtime_stats(
        tables, conds, even_counter_distr=False, drop_rate=0.25, min_tab_size=50, max_tab_size=150
    )
    json_manager = JsonManager(api=RuntimeAPI())
    runtime_states = json_manager.retrieve_runtime_states(json_path)
    ...
```

## Optimization process

A complete example is [here](examples/e2e_topk_optimization.py).

### Load json input and build IR graph
```
irg, target = JsonManager.retrieve_presplit(json_path)
```

### Compile time analysis
This process involves static analysis of the program, identifying and flagging tables that the hardware cannot fully support or can only partially support.
```
JsonManager.compile_time_json_planning(irg)
```

### Get runtime profile

```
retrieve_runtime_states.return_value = TestUtils.gen_runtime_stats(
    tables, conds, even_counter_distr=False, drop_rate=0.25, min_tab_size=50, max_tab_size=150
) # this is not needed in real usage
json_manager = JsonManager(api=RuntimeAPI())
runtime_states = json_manager.retrieve_runtime_states(json_path)
optimizer = Optimizer(api=RuntimeAPI(), sampling_period_us=1000000) # need to tune the sampling period in real usage
optimizer._update_pipeline_stats(irg, runtime_states)
```

### Pipelet partition
```
pipelets = JsonPlanner.get_pipelets(ingress_graph)
```

### Tok-k pipelet selection
```
topk = 0.3 # The top-30% of pipelets
topk_pipelets = JsonPlanner.get_topk_pipelets(pipelets, topk, OptimizeTarget.LATENCY)
```

### Compute the optimization plan

```
# set the optimization options
enabled_methods = [
    OptimizeMethod.REORDER,
    OptimizeMethod.MERGE,
    OptimizeMethod.CACHE,
]

program_option = PipeletOptimizer.reoptimize_dp(
    mavail=runtime_states.total_memory,
    iavail=runtime_states.total_entry_insertion_bandwidth,
    optimize_method=enabled_methods,
    optimize_target=OptimizeTarget.LATENCY,
    pipelets=topk_pipelets,
)
```

### Apply the optimization to IR graph
```
TestUtils.apply_pipelet_options(program_option.option, ingress_graph)
JsonDeployer.prepare_optimizer_created_tables(irg)
```

### Save the optimized program
```
irg.export_p4cirjson(path=optimized_json_path)
```

### One complete example
`examples/e2e_topk_optimization.py` provides an end-to-end example of the above process. Run it with `python3 e2e_topk_optimization.py`; you will see an optimized json file (`optimized.json`).

In the optimized json file, a new table `sirius_ingress.appliance$cch` is added, which is the cache table for `appliance` and `direction_lookup`. Also, their table order is also changed. In the original version, `direction_lookup` is before `appliance`, but the optimization swaps their order. All the changes are consistent with the printed optimization plan.

```
new_order: [1, 0] ==> ['sirius_ingress.appliance', 'sirius_ingress.direction_lookup']
>>>>>CacheOption
start_table_id: 0, length: 2 ==> ['sirius_ingress.appliance', 'sirius_ingress.direction_lookup']
```