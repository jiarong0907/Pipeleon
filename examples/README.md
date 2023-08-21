## `option_gain_cost.py`

This example shows the basic workflow of how to compute all the optimization options for a P4 program with fake runtime profiles. Results will be printed on terminals and written into a `.csv` file.

| pipelet_start | pipelet_length | mcost    | icost | lgain   | tgain | Reorder  | Softcopy | Softmove | Merge | Cache |
|---------------|----------------|----------|-------|---------|-------|----------|----------|----------|-------|-------|
| sirius_ingress.direction_lookup   | 3 | 0        | 0     | 0       | 0     | [1, 0]    | [] | [(0, 2)]   | [] | []       |
| sirius_ingress.direction_lookup   | 3 | 16000000 | 7000  | 22.26   | 2     | [1, 0]    | [] | []         | [] | [(0, 1)] |
| sirius_ingress.acl_stage1         | 2 | 83200000 | 1000  | 1454.91 | 91    | [1, 0, 2] | [] | []         | [] | [(1, 1)] |
| sirius_ingress.eni_lookup_from_vm | 3 | 6400000  | 6000  | 350.39  | 22    | [0, 2, 1] | [] | []         | [] | [(1, 2)] |
| sirius_ingress.routing            | 3 | 6400000  | 6000  | 140.72  | 9     | [0]       | [] | []         | [] | [(0, 1)] |


Results will be something like the above. It summarizes all the valid optimization options with their details.

- `pipelet_start`: The table name of the starting node for this pipelet.
- `pipelet_length`: The length of the pipelet (number of tables on this pipelet).
- `mcost`: Memory cost
- `icost`: Entry update rate cost
- `lgain`: Latency benefit
- `tgain`: Throughput benefit

The rest of the columns show the detailed optimizations. It assigns a table ID for each table in a pipelet starting from 0. For example, `Reorder [1, 0, 2]` means the new table order is table1, table0, table2, which swaps the order of the first two tables.
`Cache [(0, 1)]` means caching table0 and table1 using one cache.
