from commons.base_decorator import run_once
import commons.config as config
import os
from typing import Any, List
import yaml
from yaml.loader import SafeLoader
import commons.config as config


def get_yaml_config() -> List[Any]:
    if config.USE_CALIBRATED_COST_MODEL:
        yaml_file_name = "bluefield2_calibrated.yaml"
    else:
        yaml_file_name = "bluefield2.yaml"

    yaml_file_name = "customized_nic.yaml"

    yaml_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "..", "targets", "cost_models", yaml_file_name
    )
    with open(yaml_path, "r") as f:
        data = list(yaml.load_all(f, Loader=SafeLoader))
        return data


CPU_LATENCY = -1
DRAM_LATENCY = -1

HW_LAT_TERNARY_RATIO = -1
HW_LAT_LPM_RATIO = -1

HW_LAT_EXACT_COST = -1
HW_LAT_ACTION_COST = -1

HW_LAT_MATCH_BASE = -1
HW_LAT_ACTION_BASE = -1

HW_ACTION_LEN_STEP = -1
HW_ENTRY_SIZE = -1
HW_MEM_LEN_STEP = -1

HW_LINERATE_LATENCY = -1

SW_ENTRY_SIZE = -1
SW_MEM_LEN_STEP = -1

HW_MEM_SIZE = -1
HW_BASE_INSERT_LAT = -1
HW_BASE_DATAPATH_LAT = -1
HW_HASH_NEXT_LOOKUP_PANELTY = -1
HW_STEERING_PIPES = -1
HW_THREAD_PER_CORE = -1
HW_LOOKUP_LAT = -1
HW_TABLE_SIZE_STEP = -1

SW_ARM_CORES = -1
SW_MEM_SIZE = -1
SW_BASE_INSERT_LAT = -1
SW_BASE_LAT = -1
SW_HASH_NEXT_LOOKUP_PANELTY = -1
SW_PARSER_LAT = -1
SW_TABLE_SIZE_STEP = -1

CROSS_TARGET_MIGRATION_COST = -1


@run_once
def load_config_driver_api_impl():
    global CPU_LATENCY, DRAM_LATENCY
    global HW_LAT_TERNARY_RATIO, HW_LAT_LPM_RATIO
    global HW_ACTION_LEN_STEP, HW_ENTRY_SIZE, HW_MEM_LEN_STEP
    global SW_ENTRY_SIZE, SW_MEM_LEN_STEP

    global HW_MEM_SIZE, HW_BASE_INSERT_LAT, HW_BASE_DATAPATH_LAT, HW_HASH_NEXT_LOOKUP_PANELTY
    global HW_STEERING_PIPES, HW_THREAD_PER_CORE, HW_LOOKUP_LAT, HW_TABLE_SIZE_STEP
    global SW_ARM_CORES, SW_MEM_SIZE, SW_BASE_INSERT_LAT, SW_BASE_LAT
    global SW_HASH_NEXT_LOOKUP_PANELTY, SW_PARSER_LAT, SW_TABLE_SIZE_STEP

    global CROSS_TARGET_MIGRATION_COST

    if config.USE_CALIBRATED_COST_MODEL:
        global HW_LAT_EXACT_COST, HW_LAT_ACTION_COST
        global HW_LAT_MATCH_BASE, HW_LAT_ACTION_BASE
        global HW_LINERATE_LATENCY

    yaml_config = get_yaml_config()[0]
    CPU_LATENCY = yaml_config["cpu_latency"]
    DRAM_LATENCY = yaml_config["dram_latency"]

    HW_LAT_TERNARY_RATIO = yaml_config["hardware"]["lat_ternary_ratio"]
    HW_LAT_LPM_RATIO = yaml_config["hardware"]["lat_lpm_ratio"]
    HW_ACTION_LEN_STEP = yaml_config["hardware"]["action_len_step"]
    HW_ENTRY_SIZE = yaml_config["hardware"]["entry_size"]
    HW_MEM_LEN_STEP = yaml_config["hardware"]["mem_len_step"]

    SW_ENTRY_SIZE = yaml_config["software"]["entry_size"]
    SW_MEM_LEN_STEP = yaml_config["software"]["mem_len_step"]

    if config.USE_CALIBRATED_COST_MODEL:
        HW_LAT_EXACT_COST = yaml_config["hardware"]["lat_exact_cost"]
        HW_LAT_ACTION_COST = yaml_config["hardware"]["lat_action_cost"]
        HW_LAT_MATCH_BASE = yaml_config["hardware"]["lat_exact_base"]
        HW_LAT_ACTION_BASE = yaml_config["hardware"]["lat_action_base"]
        HW_LINERATE_LATENCY = yaml_config["hardware"]["line_rate_latency"]

    HW_MEM_SIZE = yaml_config["hardware"]["memory_size"]
    HW_BASE_INSERT_LAT = yaml_config["hardware"]["base_insertion_latency"]
    HW_BASE_DATAPATH_LAT = yaml_config["hardware"]["base_datapath_latency"]
    HW_HASH_NEXT_LOOKUP_PANELTY = yaml_config["hardware"]["hash_next_lookup_panelty"]
    HW_STEERING_PIPES = yaml_config["hardware"]["parallel_steering_pipes"]
    HW_THREAD_PER_CORE = yaml_config["hardware"]["parallel_treads_per_core"]
    HW_LOOKUP_LAT = yaml_config["hardware"]["lookup_latency"]
    HW_TABLE_SIZE_STEP = yaml_config["hardware"]["table_size_step"]

    SW_ARM_CORES = yaml_config["software"]["arm_cores"]
    SW_MEM_SIZE = yaml_config["software"]["memory_size"]
    SW_BASE_INSERT_LAT = yaml_config["software"]["base_insertion_latency"]
    SW_BASE_LAT = yaml_config["software"]["base_latency"]
    SW_HASH_NEXT_LOOKUP_PANELTY = yaml_config["software"]["hash_next_lookup_panelty"]
    SW_PARSER_LAT = yaml_config["software"]["parser_latency"]
    SW_TABLE_SIZE_STEP = yaml_config["software"]["table_size_step"]

    CROSS_TARGET_MIGRATION_COST = yaml_config["cross_target_migration_cost"]


load_config_driver_api_impl()
