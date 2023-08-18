import random
import pytest, sys, os

from commons.metric import MetricParams


class TestMetric:
    def test_metric_params_add(self):
        p99_lat1, p99_lat2 = random.randint(1, 1000), random.randint(1, 1000)
        median_lat1, median_lat2 = random.randint(1, 1000), random.randint(1, 1000)
        average_lat1, average_lat2 = random.randint(1, 1000), random.randint(1, 1000)
        inter_gap1, inter_gap2 = random.randint(1, 1000), random.randint(1, 1000)
        insert_lat1, insert_lat2 = random.randint(1, 1000), random.randint(1, 1000)
        insert_rate1, insert_rate2 = random.randint(1, 1000), random.randint(1, 1000)
        comp_util1, comp_util2 = random.randint(1, 1000), random.randint(1, 1000)
        energy_per_pkt1, energy_per_pkt2 = random.randint(1, 1000), random.randint(1, 1000)
        mem_used1, mem_used2 = random.randint(1, 1000), random.randint(1, 1000)
        mem_util1, mem_util2 = random.randint(1, 1000), random.randint(1, 1000)

        metric1 = MetricParams(
            p99_latency=p99_lat1,
            median_latency=median_lat1,
            average_latency=average_lat1,
            inter_packet_gap=inter_gap1,
            entry_insertion_latency=insert_lat1,
            entry_insertion_rate=insert_rate1,
            compute_utilization=comp_util1,
            energy_per_packet=energy_per_pkt1,
            memory_used=mem_used1,
            memory_utilization=mem_util1,
        )

        metric2 = MetricParams(
            p99_latency=p99_lat2,
            median_latency=median_lat2,
            average_latency=average_lat2,
            inter_packet_gap=inter_gap2,
            entry_insertion_latency=insert_lat2,
            entry_insertion_rate=insert_rate2,
            compute_utilization=comp_util2,
            energy_per_packet=energy_per_pkt2,
            memory_used=mem_used2,
            memory_utilization=mem_util2,
        )

        metric3 = metric1 + metric2
        assert metric3._p99_latency == p99_lat1 + p99_lat2
        assert metric3._median_latency == median_lat1 + median_lat2
        assert metric3._average_latency == average_lat1 + average_lat2
        assert metric3._inter_packet_gap == inter_gap1 + inter_gap2
        assert metric3._entry_insertion_latency == insert_lat1 + insert_lat2
        assert metric3._entry_insertion_rate == insert_rate1 + insert_rate2
        assert metric3._compute_utilization == comp_util1 + comp_util2
        assert metric3._energy_per_packet == energy_per_pkt1 + energy_per_pkt2
        assert metric3._memory_used == mem_used1 + mem_used2
        assert metric3._memory_utilization == mem_util1 + mem_util2

    def test_metric_params_iadd(self):
        p99_lat1, p99_lat2 = random.randint(1, 1000), random.randint(1, 1000)
        median_lat1, median_lat2 = random.randint(1, 1000), random.randint(1, 1000)
        average_lat1, average_lat2 = random.randint(1, 1000), random.randint(1, 1000)
        inter_gap1, inter_gap2 = random.randint(1, 1000), random.randint(1, 1000)
        insert_lat1, insert_lat2 = random.randint(1, 1000), random.randint(1, 1000)
        insert_rate1, insert_rate2 = random.randint(1, 1000), random.randint(1, 1000)
        comp_util1, comp_util2 = random.randint(1, 1000), random.randint(1, 1000)
        energy_per_pkt1, energy_per_pkt2 = random.randint(1, 1000), random.randint(1, 1000)
        mem_used1, mem_used2 = random.randint(1, 1000), random.randint(1, 1000)
        mem_util1, mem_util2 = random.randint(1, 1000), random.randint(1, 1000)

        metric1 = MetricParams(
            p99_latency=p99_lat1,
            median_latency=median_lat1,
            average_latency=average_lat1,
            inter_packet_gap=inter_gap1,
            entry_insertion_latency=insert_lat1,
            entry_insertion_rate=insert_rate1,
            compute_utilization=comp_util1,
            energy_per_packet=energy_per_pkt1,
            memory_used=mem_used1,
            memory_utilization=mem_util1,
        )

        metric2 = MetricParams(
            p99_latency=p99_lat2,
            median_latency=median_lat2,
            average_latency=average_lat2,
            inter_packet_gap=inter_gap2,
            entry_insertion_latency=insert_lat2,
            entry_insertion_rate=insert_rate2,
            compute_utilization=comp_util2,
            energy_per_packet=energy_per_pkt2,
            memory_used=mem_used2,
            memory_utilization=mem_util2,
        )

        metric1 += metric2
        assert metric1._p99_latency == p99_lat1 + p99_lat2
        assert metric1._median_latency == median_lat1 + median_lat2
        assert metric1._average_latency == average_lat1 + average_lat2
        assert metric1._inter_packet_gap == inter_gap1 + inter_gap2
        assert metric1._entry_insertion_latency == insert_lat1 + insert_lat2
        assert metric1._entry_insertion_rate == insert_rate1 + insert_rate2
        assert metric1._compute_utilization == comp_util1 + comp_util2
        assert metric1._energy_per_packet == energy_per_pkt1 + energy_per_pkt2
        assert metric1._memory_used == mem_used1 + mem_used2
        assert metric1._memory_utilization == mem_util1 + mem_util2

    def test_metric_params_sub(self):
        p99_lat1, p99_lat2 = random.randint(1, 1000), random.randint(1, 1000)
        median_lat1, median_lat2 = random.randint(1, 1000), random.randint(1, 1000)
        average_lat1, average_lat2 = random.randint(1, 1000), random.randint(1, 1000)
        inter_gap1, inter_gap2 = random.randint(1, 1000), random.randint(1, 1000)
        insert_lat1, insert_lat2 = random.randint(1, 1000), random.randint(1, 1000)
        insert_rate1, insert_rate2 = random.randint(1, 1000), random.randint(1, 1000)
        comp_util1, comp_util2 = random.randint(1, 1000), random.randint(1, 1000)
        energy_per_pkt1, energy_per_pkt2 = random.randint(1, 1000), random.randint(1, 1000)
        mem_used1, mem_used2 = random.randint(1, 1000), random.randint(1, 1000)
        mem_util1, mem_util2 = random.randint(1, 1000), random.randint(1, 1000)

        metric1 = MetricParams(
            p99_latency=p99_lat1,
            median_latency=median_lat1,
            average_latency=average_lat1,
            inter_packet_gap=inter_gap1,
            entry_insertion_latency=insert_lat1,
            entry_insertion_rate=insert_rate1,
            compute_utilization=comp_util1,
            energy_per_packet=energy_per_pkt1,
            memory_used=mem_used1,
            memory_utilization=mem_util1,
        )

        metric2 = MetricParams(
            p99_latency=p99_lat2,
            median_latency=median_lat2,
            average_latency=average_lat2,
            inter_packet_gap=inter_gap2,
            entry_insertion_latency=insert_lat2,
            entry_insertion_rate=insert_rate2,
            compute_utilization=comp_util2,
            energy_per_packet=energy_per_pkt2,
            memory_used=mem_used2,
            memory_utilization=mem_util2,
        )

        metric3 = metric1 - metric2
        assert metric3._p99_latency == p99_lat1 - p99_lat2
        assert metric3._median_latency == median_lat1 - median_lat2
        assert metric3._average_latency == average_lat1 - average_lat2
        assert metric3._inter_packet_gap == inter_gap1 - inter_gap2
        assert metric3._entry_insertion_latency == insert_lat1 - insert_lat2
        assert metric3._entry_insertion_rate == insert_rate1 - insert_rate2
        assert metric3._compute_utilization == comp_util1 - comp_util2
        assert metric3._energy_per_packet == energy_per_pkt1 - energy_per_pkt2
        assert metric3._memory_used == mem_used1 - mem_used2
        assert metric3._memory_utilization == mem_util1 - mem_util2

    def test_metric_params_isub(self):
        p99_lat1, p99_lat2 = random.randint(1, 1000), random.randint(1, 1000)
        median_lat1, median_lat2 = random.randint(1, 1000), random.randint(1, 1000)
        average_lat1, average_lat2 = random.randint(1, 1000), random.randint(1, 1000)
        inter_gap1, inter_gap2 = random.randint(1, 1000), random.randint(1, 1000)
        insert_lat1, insert_lat2 = random.randint(1, 1000), random.randint(1, 1000)
        insert_rate1, insert_rate2 = random.randint(1, 1000), random.randint(1, 1000)
        comp_util1, comp_util2 = random.randint(1, 1000), random.randint(1, 1000)
        energy_per_pkt1, energy_per_pkt2 = random.randint(1, 1000), random.randint(1, 1000)
        mem_used1, mem_used2 = random.randint(1, 1000), random.randint(1, 1000)
        mem_util1, mem_util2 = random.randint(1, 1000), random.randint(1, 1000)

        metric1 = MetricParams(
            p99_latency=p99_lat1,
            median_latency=median_lat1,
            average_latency=average_lat1,
            inter_packet_gap=inter_gap1,
            entry_insertion_latency=insert_lat1,
            entry_insertion_rate=insert_rate1,
            compute_utilization=comp_util1,
            energy_per_packet=energy_per_pkt1,
            memory_used=mem_used1,
            memory_utilization=mem_util1,
        )

        metric2 = MetricParams(
            p99_latency=p99_lat2,
            median_latency=median_lat2,
            average_latency=average_lat2,
            inter_packet_gap=inter_gap2,
            entry_insertion_latency=insert_lat2,
            entry_insertion_rate=insert_rate2,
            compute_utilization=comp_util2,
            energy_per_packet=energy_per_pkt2,
            memory_used=mem_used2,
            memory_utilization=mem_util2,
        )

        metric1 -= metric2
        assert metric1._p99_latency == p99_lat1 - p99_lat2
        assert metric1._median_latency == median_lat1 - median_lat2
        assert metric1._average_latency == average_lat1 - average_lat2
        assert metric1._inter_packet_gap == inter_gap1 - inter_gap2
        assert metric1._entry_insertion_latency == insert_lat1 - insert_lat2
        assert metric1._entry_insertion_rate == insert_rate1 - insert_rate2
        assert metric1._compute_utilization == comp_util1 - comp_util2
        assert metric1._energy_per_packet == energy_per_pkt1 - energy_per_pkt2
        assert metric1._memory_used == mem_used1 - mem_used2
        assert metric1._memory_utilization == mem_util1 - mem_util2
