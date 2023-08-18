"""
Implements Single target IrGraph
"""
from __future__ import annotations
import json
import os
import sys
import networkx as nx

# TODO - remove path handling once import issue solved
import pathlib

_ir_dir_path = pathlib.Path(__file__).parent.resolve()
base_path = os.path.abspath(os.path.join(_ir_dir_path, ".."))
sys.path.insert(0, base_path)
from ir.irgraph_pipe import IrGraphPipe
from ir.action import Action, GeneralAction
from ir.calculation import Calculation
from ir.header import Header, HeaderType
from commons.metric import MetricParams
from commons.constants import ACTION_DATA_STACK_SIZE, BITWIDTH_FOR_MAX_BITWIDTH, MAX_ACTION
from commons.types import ActionId, TableId, TableName
from commons.base_logging import logger

from typing import Any, Dict, List, Set, Tuple, TYPE_CHECKING, Type

if TYPE_CHECKING:
    from ir.table import Table


class IrGraph:
    def __init__(self, target_p4cir_desc: Dict[str, Any]):
        self._ir_pipelines: List[IrGraphPipe] = []
        self._allocated_table_ids: Set[TableId] = set()
        self._max_table_id = -1
        self._max_action_id = -1
        self._actions: List[GeneralAction] = [Action._p4cjson2ir(a) for a in target_p4cir_desc.pop("actions")]
        self._action_ids: List[ActionId] = [a.id for a in self._actions]
        self._action_id_to_name: Dict[int, str] = {action.id: action.name for action in self._actions}
        self._action_id_to_action: Dict[int, GeneralAction] = {action.id: action for action in self._actions}
        self._calculations: List[Calculation] = [
            Calculation._p4cjson2ir(c) for c in target_p4cir_desc.pop("calculations")
        ]
        self._headers: List[Header] = [Header._p4cjson2ir(h) for h in target_p4cir_desc.pop("headers")]
        self._header_types: List[HeaderType] = [
            HeaderType._p4cjson2ir(ht) for ht in target_p4cir_desc.pop("header_types")
        ]
        self._max_action_id = max(self.action_ids, default=self._max_action_id)
        self._counter_arrays = target_p4cir_desc.pop("counter_arrays")

        self._header_stacks = target_p4cir_desc.pop("header_stacks")

        for pipe in target_p4cir_desc["pipelines"]:
            self._ir_pipelines.append(
                IrGraphPipe._p4cjson2ir(
                    p4cjson=target_p4cir_desc,
                    pipe_name=pipe["name"],
                    ir_graph=self,
                )
            )
        self._max_table_id = max([t.id for pipe in self._ir_pipelines for t in pipe.tables], default=self._max_table_id)

        self._target_p4cir_desc = target_p4cir_desc  # TODO - the rest is kept here

    @property
    def actions(self) -> List[GeneralAction]:
        return self._actions

    @property
    def action_ids(self) -> List[ActionId]:
        return self._action_ids

    @property
    def action_id_to_action(self) -> Dict[int, GeneralAction]:
        assert bool(self._action_id_to_action)
        return self._action_id_to_action

    @property
    def action_id_to_name(self) -> Dict[int, str]:
        assert bool(self._action_id_to_name)
        return self._action_id_to_name

    def get_pipe_names(self) -> Tuple[str]:
        return tuple(p.ancor_point for p in self._ir_pipelines)

    def get_pipe(self, name: str) -> IrGraphPipe:
        for p in self._ir_pipelines:
            if p.ancor_point == name:
                return p
        raise NameError(f"pipe {name} not found in IrGraph. " f"Avaliable pipes: {self.get_pipe_names()}")

    def get_table(self, table_name: TableName) -> Table:
        for pipeline in self.pipelines:
            for table in pipeline.tables:
                if table.name == table_name:
                    return table
        assert False, f"Table {table_name} doesn't exist in this irgraph"

    @property
    def pipelines(self) -> List[IrGraphPipe]:
        return self._ir_pipelines

    @property
    def calculations(self) -> List[Calculation]:
        return self._calculations

    @property
    def headers(self) -> List[Header]:
        return self._headers

    @property
    def header_types(self) -> List[HeaderType]:
        return self._header_types

    @property
    def calc_name_to_calc(self) -> Dict[str, Calculation]:
        return {calc.name: calc for calc in self._calculations}

    def next_table_id(self):
        self._max_table_id += 1
        return self._max_table_id

    def next_action_id(self):
        self._max_action_id += 1
        return self._max_action_id

    def add_action_from_json(self, action_json, action_cls: Type[GeneralAction]) -> GeneralAction:
        action = action_cls._p4cjson2ir(action_json)
        self._actions.append(action)
        self._action_ids.append(action.id)
        self._action_id_to_name[action.id] = action.name
        self._action_id_to_action[action.id] = action
        return action

    def add_action_from_obj(self, action: GeneralAction) -> None:
        assert action.id not in self.action_ids, f"The action_id {action.id} already existing in the graph."
        self._actions.append(action)
        self._action_ids.append(action.id)
        self._action_id_to_name[action.id] = action.name
        self._action_id_to_action[action.id] = action

    def _add_flex_action_count_primitive(self, action: GeneralAction) -> None:
        flex_action_count_primitive = {
            "op": "count",
            "parameters": [
                {
                    "type": "counter_array",
                    "value": "$flex_action_counter",
                },
                {"type": "hexstr", "value": "{0:#0{1}x}".format(action.id, 8)},
            ],
            "source_info": {"filename": "Automated flex action counter"},
        }
        action.prepend_primitive_from_json(flex_action_count_primitive)

    def add_flex_action_counter(self) -> None:
        max_id = -1
        for counter_array in self._counter_arrays:
            assert "$flex_action_counter" != counter_array["name"], f"flex action counter already exists in the json"
            max_id = max(max_id, counter_array["id"])
        num_action_ids = -1
        for action in self.actions:
            num_action_ids = max(num_action_ids, action.id)
            self._add_flex_action_count_primitive(action)
        assert num_action_ids < MAX_ACTION, "Too many actions for flex action counter"
        flex_action_counter = {
            "id": max_id + 1,
            "is_direct": False,
            "name": "$flex_action_counter",
            "size": MAX_ACTION,
            "source_info": {"filename": "Automated flex action counter"},
        }
        self._counter_arrays.append(flex_action_counter)

    def add_action_data_stack(self) -> None:
        max_header_stack_id = -1
        for header_stack in self._header_stacks:
            assert "$action_data_stack" != header_stack["name"], f"action data stack already exists in the json"
            max_header_stack_id = max(max_header_stack_id, header_stack["id"])
        max_header_type_id = -1
        for header_type in self._header_types:
            assert "$action_data_t" != header_type.name, (
                f"$action_data_t (for action data stack design) already exists " f"in the json"
            )
            max_header_type_id = max(max_header_type_id, header_type.id)
        max_header_id = -1
        for header in self._headers:
            max_header_id = max(max_header_id, header.id)

        action_data_stack = {
            "name": "$action_data_stack",
            "id": max_header_stack_id + 1,
            "header_type": "$action_data_t",
            "size": ACTION_DATA_STACK_SIZE,
            "header_ids": [max_header_id + header_id_offset + 1 for header_id_offset in range(ACTION_DATA_STACK_SIZE)],
        }
        self._header_stacks.append(action_data_stack)
        action_data_t = HeaderType._p4cjson2ir(
            {
                "name": "$action_data_t",
                "id": max_header_type_id + 1,
                "fields": [["value", 64, False], ["bit_width", BITWIDTH_FOR_MAX_BITWIDTH, False]],
            }
        )
        self._header_types.append(action_data_t)
        for header_id_offset in range(ACTION_DATA_STACK_SIZE):
            header_id = max_header_id + header_id_offset + 1
            header = Header._p4cjson2ir(
                {
                    "name": f"$action_data_stack[{header_id_offset}]",
                    "id": header_id,
                    "header_type": "$action_data_t",
                    "metadata": False,
                    "pi_omit": True,
                }
            )
            self._headers.append(header)

    def assign_target(self, target: Any):
        """
        assign a target to the graph
        """
        for pipe in self._ir_pipelines:
            if len(pipe) > 0:
                pipe.target = target

    @classmethod
    def import_p4cirjson(cls, path: str):
        """
        generates multi-target ir from p4c ir json
        """
        # Check whether hdr., standard_metadata exists in json
        with open(path, "r") as f:
            content = f.read()
            if "hdr." not in content:
                logger.warning(f"Did not find hdr. in json. Please manually check.")
            if "standard_metadata" not in content:
                logger.warning(f"Did not find standard_metadata in json. Please manually check.")

        with open(path, "r") as f:
            p4c_ir = json.load(f)
        irg = cls(target_p4cir_desc=p4c_ir)
        irg.validate()
        return irg

    def export_p4cirjson(self, path: str):
        """
        export ir to p4c json
        """
        ir_dict = self._target_p4cir_desc
        header_type_list = []
        for ht in self.header_types:
            header_type_list.append(ht._p4cir2json())
        ir_dict["header_types"] = header_type_list

        header_list = []
        for h in self.headers:
            header_list.append(h._p4cir2json())
        ir_dict["headers"] = header_list

        pipelines_list = []
        for pi, p in enumerate(self._ir_pipelines):
            pipelines_list.append(p._p4cir2json(unique_id=pi))
        ir_dict["pipelines"] = pipelines_list

        actions_list = []
        for action in self.actions:
            actions_list.append(action._p4cir2json())
        ir_dict["actions"] = actions_list

        calculations_list = []
        for calc in self._calculations:
            calculations_list.append(calc._p4cir2json())
        ir_dict["calculations"] = calculations_list

        ir_dict["counter_arrays"] = self._counter_arrays

        ir_dict["header_stacks"] = self._header_stacks

        with open(path, "w") as f:
            json.dump(ir_dict, f, indent=4)
        print(f"Saved IR to: {path}")

    def validate(self):
        """
        Perform IR checks on each of the pipelines
        """
        for pipe in self._ir_pipelines:
            if len(pipe) > 0:
                pipe.validate()

    def eval(self) -> Dict[str, MetricParams]:
        """
        generates an evaluation of the graph performance over the assigned target
        """
        measurments = {}
        for pipe in self._ir_pipelines:
            if len(pipe) > 0:
                measurments[pipe.name] = pipe.eval()
        return measurments


def test_import_export_ir():
    """
    initial test to verify import/export/import can run
    """
    import_path = os.path.join(os.getcwd(), "tests", "sirius-pipeline", "sirius_pipeline.json")
    irg = IrGraph.import_p4cirjson(path=import_path)
    export_path = os.path.join(os.getcwd(), "tests", "sirius-pipeline", "sirius_pipeline_out.json")
    print(f"saving exported graph to: {export_path}")
    irg.export_p4cirjson(path=export_path)
    assert os.path.exists(export_path)
    irg_exported = IrGraph.import_p4cirjson(path=export_path)
    for imp_pipe in irg._ir_pipelines:
        matched = False
        for exp_pipe in irg_exported._ir_pipelines:
            if imp_pipe.ancor_point == exp_pipe.ancor_point:
                assert nx.is_isomorphic(imp_pipe, exp_pipe)
                matched = True
        assert matched, f"Pipe {imp_pipe.ancor_point} was not found in exported graph"


if __name__ == "__main__":
    test_import_export_ir()
