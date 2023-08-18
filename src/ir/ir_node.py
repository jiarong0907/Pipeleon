from abc import ABCMeta, abstractmethod

from typing import Dict, Any, Optional, Tuple
from commons.constants import DeviceTargetType, OptimizedType, OptimizedType

from commons.types import ActionName, EdgeName, LatencyPdf, Probability, TargetLoadPdf


class IrNode:
    """
    The parent class of Table and Condition
    """

    __metaclass__ = ABCMeta

    def __init__(
        self,
        name: str,
        id: int,
        target_type: DeviceTargetType = DeviceTargetType.UNASSIGNED,
        optimized_type: OptimizedType = OptimizedType.UNASSIGNED,
    ):
        self._name = name
        self._id = id
        self._target_type = target_type
        self._optimized_type = optimized_type
        self._latency_eval = None

    def __hash__(self):
        # TODO protect duplications in graph
        return hash(self.name)

    def __str__(self):
        # TODO protect duplications in graph
        return self.name

    @property
    def name(self):
        return self._name

    @property
    def id(self) -> int:
        return self._id

    @property
    def target_type(self) -> DeviceTargetType:
        """return the target that will implement this node"""
        return self._target_type

    @target_type.setter
    def target_type(self, target_type: DeviceTargetType):
        self._target_type = target_type

    @property
    def optimized_type(self) -> OptimizedType:
        """Return the optimization type of this table"""
        return self._optimized_type

    @optimized_type.setter
    def optimized_type(self, optimized_type: OptimizedType):
        self._optimized_type = optimized_type

    @property
    def latency_eval(self) -> Optional[Tuple[LatencyPdf, TargetLoadPdf]]:
        return self._latency_eval

    @latency_eval.setter
    def latency_eval(self, latency_eval):
        self._latency_eval = latency_eval

    @property
    @abstractmethod
    def desc(self):
        """used for graph visualization"""
        raise NotImplementedError(f"The class of {self.name} needs to implement desc")

    @property
    @abstractmethod
    def next_tables(self) -> Dict[str, str]:
        raise NotImplementedError(f"The class of {self.name} needs to implement next_tables")

    @property
    @abstractmethod
    def action_to_probability(self) -> Dict[ActionName, Probability]:
        raise NotImplementedError(f"The class of {self.name} needs to implement action_to_probability")

    @abstractmethod
    def update_prob_with_counts(self, edge_name_to_count: Dict[EdgeName, int]):
        raise NotImplementedError(f"The class of {self.name} needs to implement update_prob_with_counts")

    @classmethod
    @abstractmethod
    def _p4cjson2ir(cls, json_dict: Dict):
        """Creates p4cir json from expression object"""
        raise NotImplementedError(f"The class of {cls.name} needs to implement _p4cjson2ir")

    @abstractmethod
    def _p4cir2json(self) -> Dict[str, Any]:
        """
        export IrNode in p4c json ir format
        """
        raise NotImplementedError(f"The class of {self.name} needs to implement _p4cir2json")


class Root:
    name = "Root"
    desc = "Root"
    pass


class Sink:
    name = "Sink"
    desc = "Sink"
    pass
