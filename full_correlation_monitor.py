#!/usr/bin/env python3
from bcc import BPF
import psutil, time, datetime, os, csv

# --- eBPF program for syscall counting ---
bpf_text = r"""
BPF_HASH(sys_cnt, u32, u64);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u32 key = 0;
    u64 one = 1;
    u64 *val = sys_cnt.lookup(&key);
    if (val)
        (*val) += 1;
    else
        sys_cnt.update(&key, &one);
    return 0;
}
"""

b = BPF(text=bpf_text)

# --- Helper functions ---
def get_cpu_usage():
    return psutil.cpu_percent(interval=1)

def get_context_switches(prev_ctxt):
    ctxt = psutil.cpu_stats().ctx_switches
    ctxt_per_s = ctxt - prev_ctxt if prev_ctxt else 0
    return ctxt, ctxt_per_s

def get_total_packets():
    net_counters = psutil.net_io_counters(pernic=True)
    total_packets = sum(d.packets_sent + d.packets_recv for d in net_counters.values())
    return total_packets

def get_syscalls(prev_sys):
    table = b["sys_cnt"]
    keys = list(table.keys())
    syscalls = table[keys[0]].value if keys else 0
    delta = syscalls - prev_sys if prev_sys else 0
    return syscalls, delta

def estimate_energy(cpu, syscalls_s, ctx_s):
    return round((cpu * 0.4) + (syscalls_s * 0.00005) + (ctx_s * 0.0002), 2)

# --- CSV logging setup ---
log_file = "system_monitor_log.csv"
with open(log_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "cpu_percent", "packets", "delta_packets", "syscalls_per_s", "ctxswitch_per_s", "energy_estimate"])

print("Real-Time Energy-Aware System Monitor (with Logging)")
print("Logging to:", log_file)
print("Press Ctrl+C to stop\n")

prev_sys, prev_ctx, prev_pkt = 0, psutil.cpu_stats().ctx_switches, get_total_packets()

try:
    while True:
        cpu = get_cpu_usage()
        syscalls, syscalls_s = get_syscalls(prev_sys)
        packets = get_total_packets()
        delta_pkt = packets - prev_pkt
        ctxt, ctxt_s = get_context_switches(prev_ctx)
        energy = estimate_energy(cpu, syscalls_s, ctxt_s)

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] CPU: {cpu:5.1f}% |Packets: {packets:<8} |Δpkts: {delta_pkt:<5} |Syscalls/s: {syscalls_s:<6} |CtxSwitch/s: {ctxt_s:<6} |Energy ≈ {energy:6.2f} J")

        # Save data to CSV
        with open(log_file, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, cpu, packets, delta_pkt, syscalls_s, ctxt_s, energy])

        if energy > 8.0:
            print("High Energy Detected! Reducing system load...")
            os.system("renice +10 -p $(pgrep python3) >/dev/null 2>&1")
            time.sleep(3)
        elif cpu > 80:
            print("High CPU Usage! Slowing monitoring rate...")
            time.sleep(3)
        else:
            time.sleep(1)

        prev_sys, prev_ctx, prev_pkt = syscalls, ctxt, packets

except KeyboardInterrupt:
    print("\n Monitoring stopped by user.")
    print(f"Data saved in '{log_file}'")

