from __future__ import annotations  # for typing: type hints for same class only supported in python 3.10
import os, sys
from typing import TYPE_CHECKING, Dict, List, Tuple

sys.path.insert(0, os.path.abspath("."))  # TODO fix

import commons.base_warnning as base_warnning
from commons.constants import DeviceTargetType
from commons.types import LatencyPdf, NanoSec

if TYPE_CHECKING:
    from ir.table import Table

Hz = int
Bytes = int


class UnsopportedTableError(Exception):
    """Exception raised for assining unsupported table to device.

    Attributes:
        table -- table which caused the error
        message -- explanation of the error
    """

    def __init__(self, table: Table, target, reason: str = "unsupported table"):
        self.table = table
        self.target = target
        self.reason = reason
        super().__init__(self.reason)

    def __str__(self):
        return f"Table:{self.table.name} is unsupported by target:{self.target.name}.reason:\n{self.reason}"


class TargetBase:
    def __init__(self):
        pass

    def _validate_table(self, table):
        raise NotImplementedError()

    @property
    def name(self) -> str:
        return self.__class__.__name__

    @property
    def ctx(self) -> int:
        raise NotImplementedError()

    def validate_table(self, table: Table) -> Tuple[bool, str]:
        """
        Verify table compatability with target
        raises UnsopportedTableError if table is unsupported by the target.
        """
        return self._validate_table(table)

    def assign_table(self, table: Table):
        """
        Verify table with target, and sets table.target property
        raises UnsopportedTableError if table is unsupported by the target.
        """
        # target is now assigned by using optimized_type and target_type
        base_warnning.raise_deprecated_warning("This has been deprecated.")
        self._validate_table(table)
        table.target = self
        raise NotImplementedError()

    # def eval_table(self,table: Table) -> MetricParams:
    #     raise NotImplementedError(f'target {self.name} needs to implement eval_table')

    def latency_eval(self, table: Table) -> LatencyPdf:
        raise NotImplementedError()

    def get_inter_packet_gap(self, packet_latency_pdf: LatencyPdf) -> NanoSec:
        raise NotImplementedError()

    def get_memory_footprint(self, table: Table) -> Bytes:
        raise NotImplementedError()

    def get_mitigation_latency(self, next_target: TargetBase) -> NanoSec:
        raise NotImplementedError()

    def __hash__(self):
        # TODO enable mor than one core type, need unique identifier as well.
        return hash(self.name)


class MultiTargetBase:
    """
    a traget with multiple subtargets
    """

    def __init__(self, name: str, subtargets: Dict[DeviceTargetType, TargetBase]) -> None:
        self._name = name
        self._subtargets = subtargets
        pass

    @property
    def name(self) -> str:
        return self._name

    @property
    def subtargets(self) -> Dict[DeviceTargetType, TargetBase]:
        raise NotImplementedError()

    def subtarget_names(self) -> List[str]:
        raise NotImplementedError()

    @property
    def subtarget_types(self) -> List[DeviceTargetType]:
        raise NotImplementedError()

    def latency_eval(self, table: Table) -> LatencyPdf:
        assert table.target_type != None, f"Table must be assigned to a target before evaluation"
        return self._subtargets[table.target_type].latency_eval(table)

    def get_mitigation_latency(self, source_target_type: DeviceTargetType, dst_target_type: DeviceTargetType):
        src_target = self.subtargets[source_target_type]
        dst_target = self.subtargets[dst_target_type]
        return src_target.get_mitigation_latency(dst_target)

    def get_subtarget_cxt(self, subtarget_type: DeviceTargetType) -> int:
        """cxt is used for generated api to map original table entry to the owner subtarget"""
        raise NotImplementedError()
