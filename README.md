# rAthena XDP DDoS Filter

**Setup Services:** We offer professional server setup for the rAthena XDP DDoS Filter at **USD \$200 per server**.
Join our Discord for support and inquiries: [https://discord.gg/NGkMaPEKJ9](https://discord.gg/NGkMaPEKJ9)

---

This repository provides an **XDP/eBPF** program to **early-drop** unwanted TCP traffic for rAthena game server ports, offloading packet filtering from `iptables` and improving DDoS resilience.

## Performance Benchmarks

### Without OVH Protection

| Target PPS (Millions) | Approx. Gbps | CPU Cores Needed (your XDP logic) |
| --------------------- | ------------ | --------------------------------- |
| 10M                   | \~6.7 Gbps   | 1                                 |
| 30M                   | \~20 Gbps    | 3–4                               |
| 50M                   | \~33 Gbps    | 6–8                               |
| 100M                  | \~67 Gbps    | 10–14                             |
| 148M                  | \~100 Gbps   | 16–20                             |

### With OVH Protection

| Raw Attack Size | OVH Filters | Residual PPS | Cores Needed (rAthena XDP) |
| --------------- | ----------- | ------------ | -------------------------- |
| 1 Gbps          | 90%         | \~150k       | 0 (idle)                   |
| 10 Gbps         | 80–90%      | \~1.5M       | 1                          |
| 30 Gbps         | 75%         | \~6–8M       | 1–2                        |
| 50 Gbps         | 70%         | \~12–15M     | 2–3                        |
| 70 Gbps         | 65%         | \~20–25M     | 3–4                        |
| 100 Gbps        | 60–70%      | \~30–40M     | 4–6                        |

https://github.com/user-attachments/assets/4d98629b-c72d-41c0-bc64-703296942a72

## Features

* Drops all TCP packets to any of the above ports at the XDP hook level
* Near-zero CPU overhead, capable of handling 200k+ pps with <1 vCPU core
* Simple, single C file implementation with no external dependencies besides `libbpf`

## Sample Script
## File: `xdp_drop_rAthena_all_ports.c` 

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_drop_rAthena_all_ports(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __bpf_constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    switch (tcp->dest) {
        case __bpf_constant_htons(5164):
        case __bpf_constant_htons(6164):
        case __bpf_constant_htons(6964):
        case __bpf_constant_htons(11853):
        case __bpf_constant_htons(41072):
        case __bpf_constant_htons(45796):
        case __bpf_constant_htons(10001):
        case __bpf_constant_htons(10002):
        case __bpf_constant_htons(10003):
            return XDP_DROP;
        default:
            return XDP_PASS;
    }
}

char _license[] SEC("license") = "GPL";
```

## Build & Load

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt update && \
    apt install clang llvm libbpf-dev libelf-dev gcc make -y

# Compile
clang -O2 -g -target bpf \
  -c xdp_drop_rAthena_all_ports.c \
  -o xdp_drop_rAthena_all_ports.o

# Attach to interface (replace eth0)
sudo ip link set dev eth0 xdp obj xdp_drop_rAthena_all_ports.o sec xdp

# Verify
ip -details link show dev eth0

# Remove
sudo ip link set dev eth0 xdp off
```

## Metrics & Testing

* Use `hping3` to simulate floods:

  ```bash
  hping3 --rand-source --flood -S -p 5164  your.server.ip
  ```
* Check XDP counters:

  ```bash
  bpftool prog show id <prog_id>
  ```

## Extending

* **Drop counters**: add a BPF map to count drops per-port.
* **Knock & allow**: maintain an eBPF map of allowed IPs from knock ports (10001/10002).

---

*Feel free to open issues or submit PRs for improvements!*
