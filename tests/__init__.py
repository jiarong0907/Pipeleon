import os, sys

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
src_path = os.path.join(os.path.dirname(__file__), "..", "src")
test_path = os.path.join(os.path.dirname(__file__))
sys.path.insert(0, os.path.abspath(src_path))
sys.path.insert(0, os.path.abspath(test_path))
