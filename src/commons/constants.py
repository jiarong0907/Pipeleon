import enum
import os

FLEXCORE_SCRIPT = "/home/kuofeng/myGitRepos/FlexCore-private/src/main.py"
EARLY_TERM_PRIM = {"exit"}
SEGMENT_OPT_ALPHA = 3.0
STARTING_TARGET = "HwSteering"
MAX_ACTION = 256
MAX_COND = 64
MAX_PIPELET_LEN = 16
AVG_ACTION_DATA_PARAM_LEN = 2
ACTION_DATA_STACK_SIZE = MAX_PIPELET_LEN * AVG_ACTION_DATA_PARAM_LEN
# The number of bits to describe the bitwidth. For example, if the target
# supports at most 256bits throughout the p4 program, then this constant should
# be set at least 8
BITWIDTH_FOR_MAX_BITWIDTH = 16


# whether filter out large tables or high insertion rate tables for merging
# should be true for dp, and false for ml-test
ENABLE_MERGE_FILTER = True


class DeviceTargetType(enum.IntEnum):
    UNASSIGNED = -1
    HW_STEERING = 0
    SW_STEERING = 1


class OptimizedType(enum.IntEnum):
    """The type of the table after being optimized"""

    UNASSIGNED = -1
    HW_STEERING = 0
    SW_STEERING = 1
    SEMI_SUPPORTED = 2
    COPIED = 3
    CACHED = 4
    MERGED = 5
    GROUP_CACHED = 6


class OptimizeTarget(enum.IntEnum):
    LATENCY = enum.auto()
    THROUGHT = enum.auto()


class OptimizeMethod(enum.IntEnum):
    REORDER = enum.auto()
    SOFTCOPY = enum.auto()
    SOFTMOVE = enum.auto()
    MERGE = enum.auto()
    CACHE = enum.auto()


class ActionType(enum.IntEnum):
    ORIGINAL = enum.auto()
    REPLACEMENT = enum.auto()
    EXTENSION = enum.auto()
    COPY = enum.auto()
    CACHE = enum.auto()
    MERGE = enum.auto()


class CFGNodeType(enum.IntEnum):
    UNDEFINED = -1
    ROOT = 0
    SINK = 1
    IF = 2
    SWITCH = 3
    TABLE = 4


class BranchCheckResult(enum.IntEnum):
    UNDEFINED = -1
    FALSE = 0
    TRUE = 1
    SMALLER = 2


TOTAL_MEMORY = 1000000000 * 16  # Assume 16GB
TOTAL_ENTRY_INSERTION = 1000000 * 100  # Assume 100M entries/sec

TESTING_SPLIT = True


base_actions = ["goto", "drop", "na", "modiify", "learn", "forward"]  # TODO define with params.

CACHE_FOLDER_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "graph_optimizer", "cache-space")
