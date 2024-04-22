Rust-tun-nat
===
A software NAT(NAPT) written in Rust. Works as TUN device. Originates from [kazuho/rat: NAT written in pure ruby](https://github.com/kazuho/rat) (and [my fork](https://github.com/ge9/rat)).

## Warning

Although directly exposed to the internet, this software is NOT well-tested. Use at your own risk.
Also, the quality of source code may not be so high.

## Features

- Supported packets...TCP, UDP, ICMP Echo Request/Reply (outbound ping), inbound ICMP Errors (Destination Unreachable, Time Exceeded, Packet Too Big(v6))
  - Unsupported packets...IP fragment packet, SCTP, DCCP

- NAT tables (refer to RFC 4787 etc.)
  - Full Cone NAT
    - A simple 1:1 NAPT. The number of NAT mappings will be capped by the number of external ports (unlike others).
  - (quasi-) Restricted Cone NAT
    - Actually has "Address-Dependent" mapping, but tries to use the same port number for a same internal port, so behaves like EIM/ADF in most cases.
    - "NAT Type A" in Nintendo Switch.
    - Recommended if external ports are few.
  - Symmetric NAT
    - The port number is always randomized, hence APDM/APDF. Much like netfilter's SNAT/MASQUERADE with `--random`.
- Stateful inspection for TCP
  - Longer timeout for established connections
- Shows status when receiving any packets to 192.0.2.2 (an unused IP). `ping` is recommended. The packets will be dropped.
- port inserting/removing and invalid packets (doesn't match any mapping) are logged.
- Port range generator for "v6プラス", "OCNバーチャルコネクト".
- May work in Windows, with wintun.
- Static port forwarding is not supported.

## Implementation

Since mappings (or connections) have expiry time, they are stored in doubly linked list. Doubly linked list is implemented with SlotMap (or possibly with slab crate).
In NAT tables with packet inspection, each mapping have counter that indicates how many connections belong to it, and will be removed if the counter hits zero.

## Usage

```
sudo -E `which cargo` run --release
```

This creates a device "rustnat".
See https://github.com/ge9/rat/blob/main/README.md for setup.