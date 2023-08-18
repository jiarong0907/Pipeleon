from typing import Dict, Optional, Tuple
import commons.config as config
from ir.condition import Condition
from ir.ir_node import IrNode

from ir.irgraph_pipe import IrGraphPipe, Root
from ir.opt_table import ExtensionTable, OptTable
from ir.table import Table

from commons.base_logging import logger


class Reconnector:
    """To reconnect tables after optimizer generates the OptTable"""

    def __init__(self, irgraph_pipe: IrGraphPipe):
        self._irgraph_pipe: IrGraphPipe = irgraph_pipe

    def get_next_opt_tables_to_reconnect_for_normal_nodes(self, node: IrNode) -> Dict[Table, OptTable]:
        old_next_to_new_next: Dict[Table, OptTable] = {}

        for next_node_name in node.next_tables.values():
            if next_node_name is None:
                continue

            if next_node_name not in self._irgraph_pipe.name_to_normal_node:
                # TODO: Check whether disabling always works for all cases
                logger.warning("Disable connector check for reorder, merge, cache only optimization")
                # assert "$ext" in next_node_name, (
                #     f"Small test to ensure extension table is the only case "
                #     f"when a user table can point to a OptTable, but we got "
                #     f"{node.name} pointing to {next_node_name}"
                # )
                continue

            next_node = self._irgraph_pipe.name_to_normal_node[next_node_name]
            if config.GROUP_CACHE_ENABLED:
                if not (isinstance(next_node, Table) or isinstance(next_node, Condition)):
                    continue
            else:
                if not isinstance(next_node, Table):
                    continue

            opt_table = next_node.opt_table
            if opt_table and opt_table.is_to_reconnect(node):
                old_next_to_new_next[next_node] = opt_table

        return old_next_to_new_next

    def get_next_opt_table_to_reconnect_for_root(self, root: Root) -> Optional[Tuple[Table, OptTable]]:
        assert root in self._irgraph_pipe, "When reconnecting, the pipe does not have the given root"

        successors = list(self._irgraph_pipe.successors(root))
        assert len(successors) == 1, (
            f"Root should only have one successor when "
            f"get_next_opt_table_to_connect, but we got several or none: "
            f"{successors}"
        )
        next_node = successors[0]
        if config.GROUP_CACHE_ENABLED:
            if not (isinstance(next_node, Table) or isinstance(next_node, Condition)):
                return None
        else:
            if not isinstance(next_node, Table):
                return None

        next_table: Table = next_node
        opt_table = next_table.opt_table
        if opt_table and opt_table.is_to_reconnect(root):
            return (next_table, opt_table)

        return None
