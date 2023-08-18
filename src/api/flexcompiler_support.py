# This is an interface for flexcompiler (used by p4apprunner) to optimize and split the ir.
# Maybe a better way of implementing this is to move optimize_and_split_ir to Optimizer,
# but p4apprunner is written in python2, so it does not identify the typing hint supported
# from python3.
import os
import sys
import json

src_path = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.abspath(src_path))

from graph_optimizer.json_manager import JsonDeployer, JsonManager
from graph_optimizer.graph_optimizer import Optimizer
from commons.constants import DeviceTargetType
from commons.base_logging import logger
import argparse

parser = argparse.ArgumentParser(description="split p4 json output to two targets, and generates a mapping.json file")
parser.add_argument("--input_json", type=str, required=True, help="input json file path")
parser.add_argument("--output_path", type=str, required=True, help="the output directory")
args = parser.parse_args()


def optimize_and_split_ir(input_json_path: str, output_path: str):
    """
    Called by flexcompiler to optimize and get splited ir.
    """
    file_name = os.path.basename(input_json_path)
    ir_name = file_name.rstrip(".json")
    logger.info(f"input_json_path: {os.path.abspath(input_json_path)}")

    # Prepare flex_action_counter for each action
    original_irg, target = JsonManager.retrieve_presplit(input_json_path)
    original_irg.add_flex_action_counter()
    original_irg.add_action_data_stack()
    JsonDeployer.store_presplit(original_irg, input_json_path)

    optimizer = Optimizer(api=None, sampling_period_us=0, optimization_log_path="opt_compile_time.log")
    splitted_graph, mapping_dict = optimizer.do_one_time_optimize(input_json_path)
    for target_type, ir_graph in splitted_graph.items():
        target_name = "arm" if target_type == DeviceTargetType.SW_STEERING else "asic"
        export_path = os.path.join(output_path, f"{ir_name}.{target_name}_json")
        logger.info(f"saving exported graph to: {export_path}")
        ir_graph.export_p4cirjson(path=export_path)
        assert os.path.exists(export_path)

    maping_file_path = os.path.join(output_path, f"{ir_name}.mapping_json")
    with open(maping_file_path, "w") as fp:
        json.dump(mapping_dict, fp, indent=4)
        logger.info(f"saving exported graph mapping to: {maping_file_path}")


if __name__ == "__main__":
    optimize_and_split_ir(input_json_path=args.input_json, output_path=args.output_path)
