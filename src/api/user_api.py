"""
Upstream API:
Defines the API for optimization user
"""

from typdefs import *


def optimize_pipe(graph, target):
    pass


def reoptimize_pipe(original_graph, target, compiled_graph):
    """
    will get statistics from current graph to improve solution
    """
    pass


def add_entry(target, table, entry):
    pass


def remove_entry(target, table, entry):
    pass


def get_entry_counter(target, table, entry):
    pass


# TODO - complete api
