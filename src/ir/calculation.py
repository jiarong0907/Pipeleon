from dataclasses import dataclass
from typing import Dict, List, Any


@dataclass
class CalculationField:
    type: str
    value: List[str]

    def _p4cir2json(self):
        return {"type": self.type, "value": [f"{v}" for v in self.value]}

    @classmethod
    def _p4cjson2ir(cls, json) -> "CalculationField":
        type = json["type"]
        value = json["value"]
        return CalculationField(type, value)


@dataclass
class Calculation:
    name: str
    id: int
    algo: str
    input: List[CalculationField]

    @classmethod
    def _p4cjson2ir(cls, json_dict: Dict):
        name = json_dict.pop("name")
        id = json_dict.pop("id")
        algo = json_dict.pop("algo")
        input_json = json_dict.pop("input")

        calc_field: List[CalculationField] = []
        for input in input_json:
            calc_field.append(CalculationField._p4cjson2ir(input))

        assert isinstance(name, str), name
        ir_calculation = cls(name=name, id=id, algo=algo, input=calc_field)
        return ir_calculation

    def _p4cir2json(self) -> Dict[str, Any]:
        missing_source = {"filename": "offload optimizer error: missing source"}
        input_list = []
        for input in self.input:
            input_list.append(input._p4cir2json())
        condition_dict = {
            "name": self.name,
            "id": self.id,
            "algo": self.algo,
            "input": input_list,
            "source_info": missing_source,
        }
        return condition_dict
