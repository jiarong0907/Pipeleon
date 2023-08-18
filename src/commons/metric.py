"""
classes to define and evaluate cost function for optimization
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import List

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from commons.types import Bytes, Joule, NanoSec


class MetricParams:
    def __init__(
        self,
        p99_latency: NanoSec = 0,
        median_latency: NanoSec = 0,
        average_latency: NanoSec = 0,
        inter_packet_gap: NanoSec = 0,  # reverse of packet per sec. (we want higher ==> bad)
        entry_insertion_latency: NanoSec = 0,
        entry_insertion_rate: int = 0,
        memory_used: Bytes = 0,
        memory_utilization: float = 0,
        compute_utilization: float = 0,
        energy_per_packet: Joule = 0,
    ):
        self._entry_insertion_latency = entry_insertion_latency
        self._entry_insertion_rate = entry_insertion_rate
        self._median_latency = median_latency
        self._average_latency = average_latency
        self._p99_latency = p99_latency
        self._inter_packet_gap = inter_packet_gap
        self._memory_used = memory_used
        self._memory_utilization = memory_utilization
        self._compute_utilization = compute_utilization
        self._energy_per_packet = energy_per_packet

    @staticmethod
    def get_properties() -> List[str]:
        return [
            "_entry_insertion_latency",
            "_entry_insertion_rate",
            "_median_latency",
            "_average_latency",
            "_p99_latency",
            "_inter_packet_gap",
            "_memory_used",
            "_memory_utilization",
            "_compute_utilization",
            "_energy_per_packet",
        ]

    def __add__(self, other):
        result = MetricParams()
        for p in self.get_properties():
            result.__setattr__(p, self.__getattribute__(p) + other.__getattribute__(p))
        return result

    def __iadd__(self, other):
        for p in self.get_properties():
            self.__setattr__(p, self.__getattribute__(p) + other.__getattribute__(p))
        return self

    def __sub__(self, other):
        result = MetricParams()
        for p in self.get_properties():
            result.__setattr__(p, self.__getattribute__(p) - other.__getattribute__(p))
        return result

    def __isub__(self, other):
        for p in self.get_properties():
            self.__setattr__(p, self.__getattribute__(p) - other.__getattribute__(p))
        return self

    def __str__(self):
        metric_str = "[measurments] "
        metric_str += "\n[measurments] ".join([f"{p}={self.__getattribute__(p)}" for p in self.get_properties()])
        if self._inter_packet_gap > 0:
            metric_str += f"\n[measurments] max packet rate: {(1e9/self._inter_packet_gap):.2e} [1/Sec]\n"
        else:
            metric_str += f"\n[measurments] max packet rate: inf [1/Sec]\n"
        if self._entry_insertion_latency > 0:
            metric_str += (
                f"[measurments] max user rule insertion rate: {(1e9/self._entry_insertion_latency):.2e} [1/Sec]\n"
            )
        else:
            metric_str += f"[measurments] max user rule insertion rate: inf [1/Sec]\n"
        return metric_str


class MetricEvaluator:
    def __init__(self, limits: MetricParams, weights: MetricParams):
        self._limits = limits
        self._weights = weights
        self._hls = 1000  # hard limit slope

    @staticmethod
    def metric1d(meas: float, w: float, l: int, hls: int) -> float:
        x = meas / l
        return x * w + (x > 1) * (x - 1) * hls

    def eval(self, measurment: MetricParams, verbose=False) -> Cost:
        result = {}
        result_sum = 0
        for att in MetricParams.get_properties():
            result1d = self.metric1d(
                measurment.__getattribute__(att),
                self._weights.__getattribute__(att),
                self._limits.__getattribute__(att),
                self._hls,
            )
            result[att] = result1d
            result_sum += result1d
        if verbose:
            print(f"per metric attribute cost:")
            for a, v in result.items():
                print(f"[cost attr]{a} = {v:.2e}")
            print(f"Final cost: {result_sum:.2e}")
        return result_sum


@dataclass
class ProgramEvalMetric:
    org_p50_lat: NanoSec
    opt_p50_lat: NanoSec
    org_p99_lat: NanoSec
    opt_p99_lat: NanoSec
    org_avg_lat: NanoSec
    opt_avg_lat: NanoSec
    org_inter_pkt_gap: NanoSec
    opt_inter_pkt_gap: NanoSec

    @property
    def lgain_p50_absolute(self) -> NanoSec:
        """Absolute latency gain"""
        return -1 * (self.opt_p50_lat - self.org_p50_lat)

    @property
    def lgain_avg_absolute(self) -> NanoSec:
        """Absolute latency gain"""
        return -1 * (self.opt_avg_lat - self.org_avg_lat)

    @property
    def tgain_absolute(self) -> NanoSec:
        """Absolute throughput (inter packet gap) gain"""
        return -1 * (self.opt_inter_pkt_gap - self.org_inter_pkt_gap)

    @property
    def lgain_p50_relative(self) -> float:
        """Absolute p50 latency gain"""
        return self.lgain_p50_absolute * 1.0 / self.org_p50_lat

    @property
    def lgain_avg_relative(self) -> float:
        """Absolute avg latency gain"""
        return self.lgain_avg_absolute * 1.0 / self.org_avg_lat

    @property
    def tgain_relative(self) -> float:
        """Absolute throughput (inter packet gap) gain"""
        return self.tgain_absolute * 1.0 / self.org_inter_pkt_gap

    def __str__(self) -> str:
        return (
            f"================================= ProgramEvalMetric ================================\n"
            f"org_p50_lat = {self.org_p50_lat}\n"
            f"opt_p50_lat = {self.opt_p50_lat}\n"
            f"org_avg_lat = {self.org_avg_lat}\n"
            f"opt_avg_lat = {self.opt_avg_lat}\n"
            f"org_inter_pkt_gap = {self.org_inter_pkt_gap}\n"
            f"opt_inter_pkt_gap = {self.opt_inter_pkt_gap}\n"
            f"lgain_p50_absolute = {self.lgain_p50_absolute}\n"
            f"lgain_p50_relative = {self.lgain_p50_relative}\n"
            f"lgain_avg_absolute = {self.lgain_avg_absolute}\n"
            f"lgain_avg_relative = {self.lgain_avg_relative}\n"
            f"tgain_absolute = {self.tgain_absolute}\n"
            f"tgain_relative = {self.tgain_relative}\n"
        )
