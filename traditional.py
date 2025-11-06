#!/usr/bin/env python3
import psutil
import time
import datetime
import csv
import os

# === Config ===
log_file = "baseline_monitor_log.csv"
interval = 1.0  # seconds

# Remove old file if exists
if os.path.exists(log_file):
    os.remove(log_file)

# === Create CSV Header ===
with open(log_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "timestamp",
        "cpu_percent",
        "packets",
        "delta_packets",
        "syscalls_per_s",
        "ctxswitch_per_s",
        "energy_estimate"
    ])

print("Traditional CPU + System + Context Monitoring started...")
print(f"Logging to: {log_file}")
print("Press Ctrl+C to stop\n")

# === Helper to read 'processes' (syscall-like) count from /proc/stat ===
def read_syscalls_count():
    with open("/proc/stat", "r") as f:
        for line in f:
            if line.startswith("processes"):
                return int(line.split()[1])
    return 0

# === Initial readings ===
prev_pkt = psutil.net_io_counters().packets_sent + psutil.net_io_counters().packets_recv
prev_ctx = psutil.cpu_stats().ctx_switches
prev_sys = read_syscalls_count()

try:
    while True:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cpu = psutil.cpu_percent(interval=interval)
        net = psutil.net_io_counters()
        packets = net.packets_sent + net.packets_recv
        delta_pkt = packets - prev_pkt

        # Context switches
        ctx = psutil.cpu_stats().ctx_switches
        ctxswitch_s = ctx - prev_ctx

        # Approx system call rate via process creations
        sys_now = read_syscalls_count()
        syscalls_s = sys_now - prev_sys

        # Energy estimation formula same as eBPF
        energy = round((cpu * 0.4) + (syscalls_s * 0.00005) + (ctxswitch_s * 0.0002), 2)

        print(f"[{ts}] CPU: {cpu:5.1f}% | Packets: {packets:<8} | Δpkts: {delta_pkt:<5} | Syscalls/s: {syscalls_s:<6} | CtxSwitch/s: {ctxswitch_s:<6} | Energy ≈ {energy:6.2f} J")

        with open(log_file, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([ts, cpu, packets, delta_pkt, syscalls_s, ctxswitch_s, energy])

        # Update previous values
        prev_pkt = packets
        prev_ctx = ctx
        prev_sys = sys_now

except KeyboardInterrupt:
    print("\nMonitoring stopped by user.")
    print(f"Data saved in '{log_file}'")

