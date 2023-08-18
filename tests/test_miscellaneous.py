import math, os
import numpy as np
import pytest

from graph_optimizer.json_manager import JsonManager
from ir.irgraph_pipe import IrGraphPipe


class TestHitMiss:
    @pytest.mark.parametrize(
        "json_path", [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "hitmiss", "test.p4.json")]
    )
    def test_hit_miss_load(self, json_path):
        try:
            irg, target = JsonManager.retrieve_presplit(json_path)
            assert False
        except NotImplementedError:
            assert True
        except:
            assert False


class TestInterpolate:
    def test_interpolate_numpy(self):
        x = [1, 10]
        y = [1, 10]
        new_x, new_y = IrGraphPipe._stats_interpolate(x, y)
        assert new_x == list(range(1, 11))
        assert new_y == list(range(1, 11))

        x = [10]
        y = [1]
        new_x, new_y = IrGraphPipe._stats_interpolate(x, y)
        expected_x = list(range(0, 11))
        expected_y = list(np.linspace(0, 1, 11))
        assert len(new_x) == len(expected_x)
        for i in range(len(new_x)):
            assert math.isclose(new_x[i], expected_x[i])
        assert len(new_y) == len(expected_y)
        for i in range(len(new_y)):
            assert math.isclose(new_y[i], expected_y[i])

        x = [0, 4, 10]
        y = [0, 2, 10]
        new_x, new_y = IrGraphPipe._stats_interpolate(x, y)
        expected_x = list(range(0, 11))
        expected_y = [
            0.0,
            0.5,
            1.0,
            1.5,
            2.0,
            3.333333333333333,
            4.666666666666666,
            6.0,
            7.333333333333333,
            8.666666666666666,
            10.0,
        ]
        assert len(new_x) == len(expected_x)
        for i in range(len(new_x)):
            assert math.isclose(new_x[i], expected_x[i])
        assert len(new_y) == len(expected_y)
        for i in range(len(new_y)):
            assert math.isclose(new_y[i], expected_y[i])

        x = [0, 4, 10, 15]
        y = [0, 2, 8, 15]
        new_x, new_y = IrGraphPipe._stats_interpolate(x, y)
        expected_x = list(range(0, 16))
        expected_y = [0.0, 0.5, 1.0, 1.5, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.4, 10.8, 12.2, 13.6, 15.0]
        assert len(new_x) == len(expected_x)
        for i in range(len(new_x)):
            assert math.isclose(new_x[i], expected_x[i])
        assert len(new_y) == len(expected_y)
        for i in range(len(new_y)):
            assert math.isclose(new_y[i], expected_y[i])
