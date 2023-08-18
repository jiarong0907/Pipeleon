from __future__ import annotations
from abc import ABC
from dataclasses import dataclass
from typing import Dict, List, Any, Tuple, Union
from commons.types import ActionId, ActionName, ContextId
from ir.action_parameter import (
    ActionParam,
    CalculationParam,
    CounterArrayParam,
    ExpressionParam,
    FieldParam,
    HeaderParam,
    HeaderStackParam,
    HexStrParam,
    RuntimeDataParam,
    StringParam,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from commons.constants import DeviceTargetType


@dataclass
class ActionRuntimeDataItem:
    name: str
    bitwidth: int

    def _p4cir2json(self):
        return {"name": self.name, "bitwidth": self.bitwidth}


@dataclass
class ActionPrimitive:
    op: str
    parameters: List[ActionParam]

    def _p4cir2json(self):
        params = []
        for p in self.parameters:
            params.append(p._p4cir2json())
        return {"op": self.op, "parameters": params}

    @classmethod
    def _p4cjson2ir(cls, json) -> "ActionPrimitive":
        # original json has source_info, when imported source_info is ignored, so when
        # reading an exported json, there is no source_info
        assert (
            len(json.keys()) == 3
            and set(json.keys()) == {"op", "parameters", "source_info"}
            or len(json.keys()) == 2
            and set(json.keys()) == {"op", "parameters"}
        ), f"Unsupported primitives key [{json.keys()}] in json"
        op = json["op"]
        parameters: List[ActionParam] = []
        for param in json["parameters"]:
            assert len(param.keys()) == 2 and set(param.keys()) == {
                "type",
                "value",
            }, f"Unsupported parameters key in json"
            if param["type"] == "field":
                this_param = FieldParam._p4cjson2ir(param)
            elif param["type"] == "header":
                this_param = HeaderParam._p4cjson2ir(param)
            elif param["type"] == "header_stack":
                # assert param['value'] == '$action_data_stack', (
                #     f"Header stack ($action_data_stack) can only be added by "
                #     f"our compiler. We don't allow user to add header stacks, "
                #     f"but we got {param['value']}"
                # )
                this_param = HeaderStackParam._p4cjson2ir(param)
            elif param["type"] == "runtime_data":
                this_param = RuntimeDataParam._p4cjson2ir(param)
            elif param["type"] == "hexstr":
                this_param = HexStrParam._p4cjson2ir(param)
            elif param["type"] == "expression":
                this_param = ExpressionParam._p4cjson2ir(param)
            elif param["type"] == "counter_array":
                this_param = CounterArrayParam._p4cjson2ir(param)
            elif param["type"] == "calculation":
                this_param = CalculationParam._p4cjson2ir(param)
            elif param["type"] == "string":
                assert op in ["install_exact_entry_1_0", "install_cache_entry", "record_match_key",], (
                    f"Only support string with install_exact_entry_1_0, " f"install_cache_entry"
                )
                this_param = StringParam._p4cjson2ir(param)
            else:
                raise Exception(f"Unsupported action parameter type {param['type']}!")
            parameters.append(this_param)
        return ActionPrimitive(op, parameters)


class GeneralAction(ABC):
    """
    Define general table action in IR
    """

    def __init__(
        self,
        name: ActionName,
        id: ActionId,
        runtime_data: List[ActionRuntimeDataItem],
        primitives: List[ActionPrimitive],
    ):
        assert self.__class__ != GeneralAction, f"__init__ can only be used by concrete subclasses"
        self._name = name
        self._id = id
        self._runtime_data = runtime_data
        self._primitives = primitives

    @property
    def name(self) -> ActionName:
        return self._name

    @property
    def id(self) -> ActionId:
        return self._id

    @property
    def runtime_data(self) -> List[ActionRuntimeDataItem]:
        return self._runtime_data

    @property
    def primitives(self) -> List[ActionPrimitive]:
        return self._primitives

    @property
    def has_drop(self) -> bool:
        for prim in self.primitives:
            if prim.op == "exit":
                return True
        return False

    def prepend_primitive_from_json(self, prim_json):
        self._primitives.insert(0, ActionPrimitive._p4cjson2ir(prim_json))

    def _p4cir2json(self):
        runtime_data = []
        primitives = []
        for rtd in self._runtime_data:
            runtime_data.append(rtd._p4cir2json())
        for ap in self._primitives:
            primitives.append(ap._p4cir2json())
        return {"name": self._name, "id": self._id, "runtime_data": runtime_data, "primitives": primitives}

    @classmethod
    def _getjsonaction_by_id(cls, p4cjson, action_id: int) -> Dict[str, Any]:
        for a in p4cjson["actions"]:
            if a["id"] == action_id:
                return a
        raise NameError(f"action id:{action_id} not found in p4c json")

    @classmethod
    def _p4cjson2ir(cls, jsonaction) -> "GeneralAction":
        assert cls != GeneralAction, f"_p4cjson2ir can only be used by concrete subclasses"
        name = jsonaction["name"]
        id = jsonaction["id"]
        runtime_data: List[ActionRuntimeDataItem] = []
        primitives: List[ActionPrimitive] = []

        for rtd in jsonaction["runtime_data"]:
            assert len(rtd.keys()) == 2 and set(rtd.keys()) == {
                "name",
                "bitwidth",
            }, f"Unsupported runtime data key in json"
            runtime_data.append(ActionRuntimeDataItem(rtd["name"], rtd["bitwidth"]))

        for primitive in jsonaction["primitives"]:
            primitives.append(ActionPrimitive._p4cjson2ir(primitive))

        return cls(name, id, runtime_data, primitives)


class Action(GeneralAction):
    """
    Implements user-defined table action in IR
    """

    def __init__(
        self,
        name: ActionName,
        id: ActionId,
        runtime_data: List[ActionRuntimeDataItem],
        primitives: List[ActionPrimitive],
    ):
        super().__init__(name, id, runtime_data, primitives)
        self._post_opt_action_counters: List[Tuple[DeviceTargetType, ActionId]] = []

    @property
    def post_opt_action_counters(self) -> List[Tuple[DeviceTargetType, ActionId]]:
        """The device target type and action id this original action
        will be mapped to after optimization
        """
        return self._post_opt_action_counters

    @post_opt_action_counters.setter
    def post_opt_action_counters(
        self,
        in_post_opt_action_counters: List[Tuple[DeviceTargetType, ActionId]],
    ) -> None:
        self._post_opt_action_counters = in_post_opt_action_counters


class OptAction(GeneralAction):
    """
    Implements optimizer-created table action
    """

    def __init__(
        self,
        name: ActionName,
        id: ActionId,
        runtime_data: List[ActionRuntimeDataItem],
        primitives: List[ActionPrimitive],
    ):
        super().__init__(name, id, runtime_data, primitives)
        self._optimized_from: List[Action] = []

    @property
    def optimized_from(self) -> List[Action]:
        """Actions that this opt action was optimized from

        Note that if optimized_from has this action itself, it means this action
        is copied from another context using the same action_id
        """
        return self._optimized_from

    @optimized_from.setter
    def optimized_from(self, actions: List[Action]) -> None:
        self._optimized_from = actions


@dataclass
class ConditionAction(GeneralAction):
    """
    Fake action for conditions. Used by group cache to generate compound actions
    """

    def __init__(self, name: ActionName, id: ActionId, next_node: str):
        super().__init__(name, id, [], [])
        self._next_node = next_node
        self._post_opt_action_counters: List[Tuple[DeviceTargetType, ActionId]] = []

    @property
    def next_node(self) -> str:
        return self._next_node

    # TODO: @Kuo-Feng check this
    @property
    def post_opt_action_counters(self) -> List[Tuple[DeviceTargetType, ActionId]]:
        """The device target type and action id this original action
        will be mapped to after optimization
        """
        return self._post_opt_action_counters

    @post_opt_action_counters.setter
    def post_opt_action_counters(
        self,
        in_post_opt_action_counters: List[Tuple[DeviceTargetType, ActionId]],
    ) -> None:
        self._post_opt_action_counters = in_post_opt_action_counters
