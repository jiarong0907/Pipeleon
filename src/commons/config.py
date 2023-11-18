import pytest_is_running

GROUP_CACHE_ENABLED = False

USE_CALIBRATED_COST_MODEL = False
# This should only be enabled for the pipelet benchmark experiments
# and the topk group experiments
DISABLE_BASE_LATENCY = True

ENABLE_CACHE_HIT_RATE_CHANGE = True

# How many caches a pipelet can have
MAX_PER_PIPELET_CACHE = 1

# Whether the cache rate should decrease with the number of cached tables
CACHE_HIT_RATE_CHANGE_STEP = True

if pytest_is_running.is_running():
    DP_MSTEP = 100000000
    DP_ISTEP = 10000000
    CACHE_TABLE_SIZE = 1000
    CACHE_HIT_RATE = 0.95
    MERGE_HIT_RATE = 0.95
    USE_CALIBRATED_COST_MODEL = False
    GROUP_CACHE_ENABLED = True
    MAX_PER_PIPELET_CACHE = 1
    ENABLE_CACHE_HIT_RATE_CHANGE = False
    CACHE_HIT_RATE_CHANGE_STEP = False
else:
    DP_MSTEP = 100000000
    DP_ISTEP = 1000000
    CACHE_TABLE_SIZE = 1000
    CACHE_HIT_RATE = 0.8
    MERGE_HIT_RATE = 0.95

# Table merge will be considered if <= this threshold
MERGE_INSERT_RATE_THRESHOLD = 10
MERGE_TABLE_SIZE_THRESHOLD = 100

# TOPK used by BMv2
FLEX_CONTROL_TOPK = 0.3

# The threshold to update counter and the probibility
COUNTER_UPDATE_THRESHOLD = 1
