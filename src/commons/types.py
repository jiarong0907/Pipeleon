"""
Type defs for smart acc IR
"""
from typing import List, Tuple, Dict, Any, Union

from commons.constants import DeviceTargetType
from commons.metric import MetricParams

# for IR
Target = str
Name = str
TableName = str
CondName = str
ActionId = int
TableId = int
HeaderId = int
HeaderName = str
tHeaderType = str
tHeaderField = str
IrNodeName = str
ActionName = str
BranchName = str
EdgeName = Union[ActionName, BranchName]
ActionData = str
TargetName = str
ConstEntries = List[Dict[str, Any]]
OptTypeStr = str

# For cost model
Probability = float
MicroSec = int
NanoSec = int
CoreCycles = int
Bytes = int
LatencyPdf = List[Tuple[NanoSec, Probability]]
CoreCyclesPdf = List[Tuple[CoreCycles, Probability]]
Cost = float
Joule = float

# For mapping generation
ContextId = int
ActionInfo = Tuple[ActionId, ContextId]
ActionStrId = Tuple[TableName, ActionName]
ActionInfoMap = Dict[ActionStrId, ActionInfo]


TargetLoadPdf = Dict[DeviceTargetType, CoreCyclesPdf]
TargetMeas = Dict[DeviceTargetType, MetricParams]
