from __future__ import annotations
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
import enum
from typing import Dict, List, Tuple, Union, Optional, Any

from typing import TYPE_CHECKING

from ir.calculation import Calculation

if TYPE_CHECKING:
    from ir.irgraph import IrGraph


class PARAMTYPE(enum.IntEnum):
    FIELD = enum.auto()
    HEADER = enum.auto()
    HEADER_STACK = enum.auto()
    RUNTIME_DATA = enum.auto()
    HEX_STR = enum.auto()
    COUNTER_ARRAY = enum.auto()
    STRING = enum.auto()
    CALCULATION = enum.auto()
    LOCAL = enum.auto()
    BOOL = enum.auto()
    EXPRESSION = enum.auto()

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        # I presume that the 'value' is not a mutable object
        return self


class ActionParam:
    __metaclass__ = ABCMeta

    def __init__(self, type: PARAMTYPE, value: Any) -> None:
        self._type = type
        self._value = value

    @property
    def type(self) -> PARAMTYPE:
        return self._type

    @type.setter
    def type(self, type):
        raise Exception("type is a read-only field")

    @property
    def value(self) -> Any:
        return self._value

    @value.setter
    def value(self, value: Any):
        self._value = value

    @abstractmethod
    def _p4cir2json(self):
        pass

    @abstractmethod
    def _p4cjson2ir(self):
        pass


class FieldParam(ActionParam):
    def __init__(self, value: List[str]) -> None:
        super().__init__(PARAMTYPE.FIELD, value)

    @property
    def value(self) -> List[str]:
        return self._value

    @value.setter
    def value(self, value: List[str]):
        self._value = value

    def _p4cir2json(self):
        return {"type": "field", "value": [f"{v}" for v in self._value]}

    @classmethod
    def _p4cjson2ir(cls, json) -> "FieldParam":
        type = json["type"]
        value = json["value"]
        assert type == "field", f"The type value of FieldParam must be field"
        return FieldParam(value)


class HeaderParam(ActionParam):
    def __init__(self, value: str) -> None:
        super().__init__(PARAMTYPE.HEADER, value)

    @property
    def value(self) -> str:
        return self._value

    @value.setter
    def value(self, value: str):
        self._value = value

    def _p4cir2json(self):
        return {"type": "header", "value": self._value}

    @classmethod
    def _p4cjson2ir(cls, json) -> "HeaderParam":
        type = json["type"]
        value = json["value"]
        assert type == "header", f"The type value of HeaderParam must be header"
        return HeaderParam(value)


class HeaderStackParam(ActionParam):
    def __init__(self, value: str) -> None:
        super().__init__(PARAMTYPE.HEADER_STACK, value)

    @property
    def value(self) -> str:
        return self._value

    @value.setter
    def value(self, value: str):
        self._value = value

    def _p4cir2json(self):
        return {"type": "header_stack", "value": self._value}

    @classmethod
    def _p4cjson2ir(cls, json) -> "HeaderStackParam":
        type = json["type"]
        value = json["value"]
        assert type == "header_stack", f"The type value of HeaderParam must be header"
        return HeaderStackParam(value)


class RuntimeDataParam(ActionParam):
    def __init__(self, value: int) -> None:
        super().__init__(PARAMTYPE.RUNTIME_DATA, value)

    @property
    def value(self) -> int:
        return self._value

    @value.setter
    def value(self, value: int):
        self._value = value

    def _p4cir2json(self):
        return {"type": "runtime_data", "value": self._value}

    @classmethod
    def _p4cjson2ir(cls, json) -> "RuntimeDataParam":
        type = json["type"]
        value = json["value"]
        assert type == "runtime_data", f"The type value of RuntimeDataParam must be runtime_data"
        return RuntimeDataParam(value)


class HexStrParam(ActionParam):
    def __init__(self, value: str) -> None:
        super().__init__(PARAMTYPE.HEX_STR, value)

    @property
    def value(self) -> str:
        return self._value

    @value.setter
    def value(self, value: str):
        self._value = value

    def _p4cir2json(self):
        return {"type": "hexstr", "value": self._value}

    @classmethod
    def _p4cjson2ir(cls, jsonparam) -> "HexStrParam":
        type = jsonparam["type"]
        value = jsonparam["value"]
        assert type == "hexstr", f"The type value of HexStrParam must be hexstr"
        return HexStrParam(value)


class CounterArrayParam(ActionParam):
    def __init__(self, value: str) -> None:
        super().__init__(PARAMTYPE.COUNTER_ARRAY, value)

    @property
    def value(self) -> str:
        return self._value

    @value.setter
    def value(self, value: str):
        self._value = value

    def _p4cir2json(self):
        return {"type": "counter_array", "value": self._value}

    @classmethod
    def _p4cjson2ir(cls, json) -> "CounterArrayParam":
        type = json["type"]
        value = json["value"]
        assert type == "counter_array", f"The type value of CounterArrayParam must be counter_array"
        return CounterArrayParam(value)


class StringParam(ActionParam):
    def __init__(self, value: str) -> None:
        super().__init__(PARAMTYPE.STRING, value)

    @property
    def value(self) -> str:
        return self._value

    @value.setter
    def value(self, value: str):
        self._value = value

    def _p4cir2json(self):
        return {"type": "string", "value": self._value}

    @classmethod
    def _p4cjson2ir(cls, json) -> "StringParam":
        type = json["type"]
        value = json["value"]
        assert type == "string", f"The type value of StringParam must be string"
        return StringParam(value)


class CalculationParam(ActionParam):
    def __init__(self, value: str) -> None:
        super().__init__(PARAMTYPE.CALCULATION, value)

    @property
    def value(self) -> str:
        return self._value

    @value.setter
    def value(self, value: str):
        self._value = value

    def _p4cir2json(self):
        return {"type": "calculation", "value": self._value}

    def _get_variables(self, irg: IrGraph) -> List[ActionParam]:
        calc: Calculation = irg.calc_name_to_calc[self.value]
        var_list: List[ActionParam] = []
        for input in calc.input:
            if input.type == "field":
                var_list.append(FieldParam(input.value))
            elif input.type in ["runtime_data", "local", "hexstr"]:
                pass  # we don't care about constants
            else:
                raise Exception("Unexpected type for Calculation")
        return var_list

    @classmethod
    def _p4cjson2ir(cls, json) -> "CalculationParam":
        type = json["type"]
        value = json["value"]
        assert type == "calculation", f"The type value of CalculationParam must be calculation"
        return CalculationParam(value)


class LocalParam(ActionParam):
    def __init__(self, value: int) -> None:
        super().__init__(PARAMTYPE.LOCAL, value)

    @property
    def value(self) -> int:
        return self._value

    @value.setter
    def value(self, value: int):
        self._value = value

    def _p4cir2json(self):
        return {"type": "local", "value": self._value}

    @classmethod
    def _p4cjson2ir(cls, json) -> "LocalParam":
        type = json["type"]
        value = json["value"]
        assert type == "local", f"The type value of LocalParam must be local"
        return LocalParam(value)


class BoolParam(ActionParam):
    def __init__(self, value: bool) -> None:
        super().__init__(PARAMTYPE.BOOL, value)

    @property
    def value(self) -> bool:
        return self._value

    @value.setter
    def value(self, value: bool):
        self._value = value

    def _p4cir2json(self):
        return {"type": "bool", "value": self._value}

    @classmethod
    def _p4cjson2ir(cls, json) -> "BoolParam":
        type = json["type"]
        value = json["value"]
        assert type == "bool", f"The type value of BoolParam must be bool"
        return BoolParam(value)


class ExpressionParam(ActionParam):
    def __init__(self, value: Union["ExpressionParam", "ExpressionBody"]) -> None:
        super().__init__(PARAMTYPE.EXPRESSION, value)

    @property
    def value(self) -> Union["ExpressionParam", "ExpressionBody"]:
        return self._value

    @value.setter
    def value(self, value: Union["ExpressionParam", "ExpressionBody"]):
        self._value = value

    def _get_variables(self, irg: IrGraph) -> List[ActionParam]:
        """Return all variables used by this expression"""
        return self.value._get_variables(irg)

    def _p4cir2json(self):
        return {"type": "expression", "value": self._value._p4cir2json()}

    @classmethod
    def _p4cjson2ir(cls, json) -> "ExpressionParam":
        type = json["type"]
        value_dict = json["value"]
        assert type == "expression", f"The type value of ExpressionParam must be expression"

        # The value is an expressionparam
        if "type" in value_dict.keys():
            value = cls._p4cjson2ir(value_dict)
        # The value is an expression body
        else:
            value = ExpressionBody._p4cjson2ir(value_dict)

        return ExpressionParam(value)


ExpressionLeft = Union[FieldParam, HeaderParam, ExpressionParam, HexStrParam, LocalParam, BoolParam]
ExpressionRight = Union[FieldParam, HeaderParam, ExpressionParam, RuntimeDataParam, HexStrParam, LocalParam, BoolParam]


@dataclass
class ExpressionBody:
    op: str
    left: Optional[ExpressionLeft]
    right: ExpressionRight

    def _get_variables_left_right(
        self, irg: IrGraph, oprand: Union[ExpressionLeft, ExpressionRight]
    ) -> List[ActionParam]:
        var: List[ActionParam] = []
        if isinstance(oprand, FieldParam) or isinstance(oprand, HeaderParam):
            var.append(oprand)
        elif isinstance(oprand, ExpressionParam) or isinstance(oprand, CalculationParam):
            var += oprand._get_variables(irg)
        elif isinstance(oprand, RuntimeDataParam) or isinstance(oprand, LocalParam) or isinstance(oprand, HexStrParam):
            pass  # we don't care about constants
        else:
            raise Exception("Unexpected instance type for expression body")

        return var

    def _get_variables(self, irg: IrGraph) -> List[ActionParam]:
        """Return all variables used by this expression body"""
        left_var: List[ActionParam] = []
        if self.left != None:
            left_var = self._get_variables_left_right(irg, self.left)
        right_var: List[ActionParam] = self._get_variables_left_right(irg, self.right)
        return left_var + right_var

    def _p4cir2json(self):
        return {
            "op": self.op,
            "left": None if self.left == None else self.left._p4cir2json(),
            "right": self.right._p4cir2json(),
        }

    def _p4cjson2ir_expression_left(self, json) -> ExpressionLeft:
        type = json["type"]
        if type == "field":
            this_left = FieldParam._p4cjson2ir(json)
        elif type == "header":
            this_left = HeaderParam._p4cjson2ir(json)
        elif type == "runtime_data":
            this_left = RuntimeDataParam._p4cjson2ir(json)
        elif type == "expression":
            this_left = ExpressionParam._p4cjson2ir(json)
        elif type == "hexstr":
            this_left = HexStrParam._p4cjson2ir(json)
        elif type == "local":
            this_left = LocalParam._p4cjson2ir(json)
        elif type == "bool":
            this_left = BoolParam._p4cjson2ir(json)
        else:
            raise Exception(f"Unexpected type {type} for expression left.")
        return this_left

    def _p4cjson2ir_expression_right(self, json) -> ExpressionRight:
        type = json["type"]
        if type == "field":
            this_right = FieldParam._p4cjson2ir(json)
        elif type == "header":
            this_right = HeaderParam._p4cjson2ir(json)
        elif type == "runtime_data":
            this_right = RuntimeDataParam._p4cjson2ir(json)
        elif type == "hexstr":
            this_right = HexStrParam._p4cjson2ir(json)
        elif type == "local":
            this_right = LocalParam._p4cjson2ir(json)
        elif type == "bool":
            this_right = BoolParam._p4cjson2ir(json)
        elif type == "expression":
            this_right = ExpressionParam._p4cjson2ir(json)
        else:
            raise Exception(f"Unexpected type for expression right {type}.")
        return this_right

    @classmethod
    def _p4cjson2ir(cls, json) -> "ExpressionBody":
        op = json["op"]
        if json["left"] == None:
            left = None
        else:
            left = cls._p4cjson2ir_expression_left(cls, json["left"])
        right = cls._p4cjson2ir_expression_right(cls, json["right"])
        return ExpressionBody(op, left, right)
