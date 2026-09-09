#!/usr/bin/env python3

import csv
import glob
import math
import statistics
import sys

# Student's t critical value for a two-sided 95% CI with 9 degrees of freedom.
T_CRITICAL_N10 = 2.262
TARGET_SWITCH_COUNTS = {5, 10, 20, 30}

pattern = sys.argv[1] if len(sys.argv) > 1 else "results/scalability_*.csv"
measurements = {}

for filename in glob.glob(pattern):
    with open(filename, newline="") as csv_file:
        rows = list(csv.DictReader(csv_file))

    if not rows:
        continue

    # batch_us is repeated once for every switch. Keep one value per round.
    for row in rows:
       switches = int(row["switches"])

       if switches not in TARGET_SWITCH_COUNTS:
           continue

       key = (
           row["configuration"],
           switches,
           int(row["repetition"]),
       )
       measurements[key] = float(row["batch_us"]) / 1000.0

groups = {}
for (configuration, switches, repetition), latency_ms in measurements.items():
    groups.setdefault((switches, configuration), []).append(latency_ms)

print(
    "switches,configuration,n,mean_ms,median_ms,sd_ms,"
    "ci_low_ms,ci_high_ms,ci_half_ms,min_ms,max_ms"
)

for (switches, configuration), values in sorted(groups.items()):
    values = sorted(values)
    n = len(values)

    if n != 10:
        raise ValueError(
            f"{configuration} n={switches}: expected 10 rounds, found {n}"
        )

    mean = statistics.mean(values)
    median = statistics.median(values)
    sd = statistics.stdev(values)
    ci_half = T_CRITICAL_N10 * sd / math.sqrt(n)

    print(
        f"{switches},{configuration},{n},"
        f"{mean:.3f},{median:.3f},{sd:.3f},"
        f"{mean - ci_half:.3f},{mean + ci_half:.3f},"
        f"{ci_half:.3f},{min(values):.3f},{max(values):.3f}"
    )
