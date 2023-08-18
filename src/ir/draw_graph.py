"""
dashboard for visulaization of the IR at different stages, and for different pipelines.
"""


import os
import sys
from commons import types
from networkx import exception
import streamlit as st
import streamlit.components.v1 as components
import networkx as nx
import pathlib

_ir_dir_path = pathlib.Path(__file__).parent.resolve()
base_path = os.path.abspath(os.path.join(_ir_dir_path, ".."))
print(base_path)
sys.path.insert(0, base_path)

from pyvis.network import Network
from math import log2
from ir.irgraph import IrGraph, IrGraphPipe
from ir.ir_node import Root, Sink
from ir import table

# label, title, gorup

st.title("P4 pipeline plotter")


def get_node_size(node) -> int:
    try:
        return int(log2(node.max_size)) + 10
    except AttributeError:
        return 10


def p4_opt_ir(irg_pipe: IrGraphPipe):
    d_graph = nx.DiGraph()
    # st.title(f'P4 pipeline plotter: {irgraph.name}')
    for n in irg_pipe.nodes:
        if isinstance(n, Root) or isinstance(n, Sink):
            continue
        d_graph.add_node(n.name, size=get_node_size(n), title=n.desc, physics=False)
    for e in irg_pipe.edges:
        if isinstance(e[0], Root) or isinstance(e[1], Sink):
            continue
        prob_list = ""
        try:
            # assuming table
            for k, v in e[0].next_tables.items():
                if v[0] == e[1].name:
                    prob_list += f"{k}:{v[1]}<br>"
        except AttributeError:
            # assuming condition
            if e[0].true_next == e[1].name:
                prob_list = f"True:{e[0].true_probability}"
            else:
                prob_list = f"False:{1.-e[0].true_probability}"
        edge_data = irg_pipe.get_edge_data(*e)
        d_graph.add_edge(e[0].name, e[1].name, title=prob_list, weight=edge_data["probability"])

    draw_graph = Network("700px", "100%", notebook=True, heading="", directed=True)
    draw_graph.from_nx(d_graph)
    # physics=st.sidebar.checkbox('add physics interactivity?')
    # if physics:
    #     nt.show_buttons(filter_=['nodes', 'edges', 'layout', 'interaction', 'manipulation', 'physics', 'selection', 'renderer'])
    draw_graph.show("p4_opt_ir.html")


st.sidebar.title("Choose Pipeline")
# path = os.path.abspath(os.path.join(_ir_dir_path,'..','..','tests','andromeda'))
path = os.path.abspath(os.path.join(_ir_dir_path, "..", "..", "tests", "simple_test_no_const_action"))
p4cirs = []
for f in os.listdir(path):
    if f.endswith(".json"):
        p4cirs.append(f)
ir_option = st.sidebar.selectbox("select ir to import", tuple(p4cirs))
if ir_option:
    irg = IrGraph.import_p4cirjson(os.path.join(path, ir_option))
    pipe_option = st.sidebar.selectbox("select pipeline", irg.get_pipe_names())
    if pipe_option:
        # _physics=st.sidebar.checkbox('add physics interactivity?')
        p4_opt_ir(irg.get_pipe(pipe_option))
        HtmlFile = open("p4_opt_ir.html", "r", encoding="utf-8")
        source_code = HtmlFile.read()
        components.html(source_code, height=1200, width=1000)
