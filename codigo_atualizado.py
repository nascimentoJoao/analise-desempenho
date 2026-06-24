#!/usr/bin/env python3
from bcc import BPF
import time
import argparse
import subprocess
import psutil
import csv

BPF_PROGRAM = r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>

BPF_ARRAY(counters, u64, 8);

#define PACKETS_TOTAL 0
#define XDP_PASS_CNT  1
#define XDP_DROP_CNT  2
#define EVENTS_SENT   3

BPF_PERF_OUTPUT(events);

struct event_t {
    u64 timestamp;
    u32 action;
    u32 pkt_len;
};

int xdp_markov(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    u32 key;
    u64 *value;

    key = PACKETS_TOTAL;
    value = counters.lookup(&key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }

    int pkt_len = data_end - data;

    /*
     * Amostragem:
     * envia evento ao user-space a cada 100 pacotes.
     */
    key = PACKETS_TOTAL;
    value = counters.lookup(&key);

    if (value && ((*value % 100) == 0)) {
        struct event_t event = {};
        event.timestamp = bpf_ktime_get_ns();
        event.action = XDP_PASS;
        event.pkt_len = pkt_len;

        events.perf_submit(ctx, &event, sizeof(event));

        key = EVENTS_SENT;
        value = counters.lookup(&key);
        if (value) {
            __sync_fetch_and_add(value, 1);
        }
    }

    key = XDP_PASS_CNT;
    value = counters.lookup(&key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }

    return XDP_PASS;
}
"""

def read_softnet_drops():
    drops = 0

    with open("/proc/net/softnet_stat", "r") as f:
        for line in f:
            cols = line.split()

            if len(cols) > 1:
                drops += int(cols[1], 16)

    return drops


def read_nic_drops(interface):
    try:
        output = subprocess.check_output(
            ["ethtool", "-S", interface],
            stderr=subprocess.DEVNULL,
            text=True
        )

        total = 0

        for line in output.splitlines():
            line_lower = line.lower()

            if (
                "drop" in line_lower
                or "miss" in line_lower
                or "error" in line_lower
            ):
                parts = line.strip().split(":")

                if len(parts) == 2:
                    try:
                        total += int(parts[1].strip())
                    except ValueError:
                        pass

        return total

    except Exception:
        return 0


def classify_state(cpu_max, pps, rx_drop_delta, lost_events_delta):
    """
    Estados da cadeia de Markov:

    N = Normal
    H = Alta carga
    C = CPU saturada
    R = RX DROP real
    P = Perf ring cheio
    """

    if lost_events_delta > 100:
        return "P"

    if rx_drop_delta > 0:
        return "R"

    if cpu_max >= 90:
        return "C"

    if cpu_max >= 65 or pps > 200000:
        return "H"

    return "N"


def main():
    parser = argparse.ArgumentParser(
        description="Monitor eBPF/XDP para mapear estados da cadeia de Markov"
    )

    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help="Interface de rede, ex: enp5s0"
    )

    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Nome do arquivo CSV de saída, ex: teste_baixa_carga.csv"
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Intervalo de coleta em segundos"
    )

    args = parser.parse_args()

    csv_filename = args.output

    csv_file = open(csv_filename, mode="a", newline="")
    csv_writer = csv.writer(csv_file)

    csv_writer.writerow([
        "timestamp",
        "state",
        "cpu_avg_percent",
        "cpu_max_percent",
        "pps",
        "rx_drops_delta",
        "events_sent",
        "events_lost_delta",
        "xdp_pass",
        "xdp_drop"
    ])

    csv_file.flush()

    b = BPF(
        text=BPF_PROGRAM,
        cflags=[
            "-Wno-duplicate-decl-specifier"
        ]
    )

    fn = b.load_func("xdp_markov", BPF.XDP)
    b.attach_xdp(args.interface, fn, 0)

    print(f"[+] XDP carregado na interface {args.interface}")
    print(f"[+] CSV: {csv_filename}")
    print("[+] Amostragem ativa: 1 evento a cada 100 pacotes")
    print("[+] XDP_DROP artificial removido")
    print("[+] Estado R ocorre somente se RX_DROP real > 0")
    print("[+] Estado P ocorre se EVENTS_LOST+ > 100")
    print("[+] Estado C ocorre se CPU_MAX >= 90%")
    print("[+] Estado H ocorre se CPU_MAX >= 65% ou PPS > 200000")
    print("[+] Warnings de duplicate-decl-specifier silenciados")
    print("[+] Pressione CTRL+C para parar\n")

    counters = b["counters"]

    last_packets = 0

    last_softnet_drops = read_softnet_drops()
    last_nic_drops = read_nic_drops(args.interface)

    lost_events = 0
    last_lost_events = 0

    line_count = 0
    last_events_printed = 0

    def handle_event(cpu, data, size):
        pass

    def handle_lost(count):
        nonlocal lost_events
        lost_events += count

    b["events"].open_perf_buffer(
        handle_event,
        lost_cb=handle_lost,
        page_cnt=1024
    )

    try:
        while True:
            b.perf_buffer_poll(timeout=100)

            time.sleep(args.interval)

            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

            packets = counters[0].value
            xdp_pass = counters[1].value
            xdp_drop = counters[2].value
            events_sent = counters[3].value

            pps = (packets - last_packets) / args.interval
            last_packets = packets

            cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
            cpu_avg = sum(cpu_per_core) / len(cpu_per_core)
            cpu_max = max(cpu_per_core)

            current_softnet_drops = read_softnet_drops()
            current_nic_drops = read_nic_drops(args.interface)

            rx_drop_delta = (
                current_softnet_drops - last_softnet_drops
            ) + (
                current_nic_drops - last_nic_drops
            )

            last_softnet_drops = current_softnet_drops
            last_nic_drops = current_nic_drops

            lost_events_delta = lost_events - last_lost_events
            last_lost_events = lost_events

            state = classify_state(
                cpu_max,
                pps,
                rx_drop_delta,
                lost_events_delta
            )

            if (events_sent - last_events_printed) >= 10:

                if line_count % 20 == 0:
                    print(
                        "\nSTATE | CPU_MAX | CPU_AVG | PPS      | RX_DROP | LOST | EVENTS | PASS"
                    )
                    print(
                        "------+---------+---------+----------+---------+------+--------+--------"
                    )

                print(
                    f"{state:^5} | "
                    f"{cpu_max:7.1f} | "
                    f"{cpu_avg:7.1f} | "
                    f"{pps:8.0f} | "
                    f"{rx_drop_delta:7d} | "
                    f"{lost_events_delta:4d} | "
                    f"{events_sent:6d} | "
                    f"{xdp_pass:6d}"
                )

                last_events_printed = events_sent
                line_count += 1

            csv_writer.writerow([
                timestamp,
                state,
                round(cpu_avg, 2),
                round(cpu_max, 2),
                round(pps, 2),
                rx_drop_delta,
                events_sent,
                lost_events_delta,
                xdp_pass,
                xdp_drop
            ])

            csv_file.flush()

    except KeyboardInterrupt:
        print("\n[+] Removendo XDP...")

    finally:
        csv_file.close()
        b.remove_xdp(args.interface, 0)
        print("[+] XDP removido.")
        print(f"[+] CSV salvo em: {csv_filename}")


if __name__ == "__main__":
    main()
