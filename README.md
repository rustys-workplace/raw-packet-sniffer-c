# Zero-Dependency Raw Packet Sniffer in C

A high-performance, low-level network analyzer built from scratch in C. This tool bypasses standard application-layer wrappers (like `libpcap`) to interact directly with the Linux kernel network subsystem, capturing and decoding live network traffic from a local interface.

---

## 🚀 Key Features

* **Kernel Interface Customization:** Bypasses standard sockets to hook into the Link Layer (`AF_PACKET`, `SOCK_RAW`), dynamically modifying network interface flags via `ioctl` to enable **Promiscuous Mode**.
* **Layer 2/3 Dynamic Structural Mapping:** Processes raw byte streams on the fly by overlaying standard Linux definitions (`struct ethhdr` and `struct iphdr`) onto the memory buffer using pointer arithmetic.
* **Variable IP Header Parsing:** Dynamically shifts pointers to read Layer 4 configurations based on the IP header's variable length ($IHL \times 4$).
* **TCP Flag Demultiplexing:** Isolates network traffic to strictly monitor TCP segments, filtering out UDP/ICMP noise and extracting active communication control signals (`SYN`, `ACK`, `FIN`, `PSH`, `RST`, `URG`).
* **Security Payload Hex Engine:** Features a side-by-side hexadecimal and ASCII loop engine that securely displays raw packet payload data while filtering out non-printable binary junk.

---

## 🛠️ Architecture Blueprint
[ Network Interface Card (wlo1 / usb0) ]
                      |
                      v  (Promiscuous Mode enabled via ioctl)
         [ Layer 2: struct ethhdr ]
                      |
                      v  (Filter out non-IPv4 traffic)
          [ Layer 3: struct iphdr ]
                      |
                      v  (Pointer shift via IHL calculation)
         [ Layer 4: struct tcphdr ]
                      |
                      v  (Filter out UDP/ICMP, read flags)
         [ Raw Payload Forensics Engine ] -> Hex/ASCII Grid
---

## 📋 System Requirements

* **Operating System:** Linux (Ubuntu, Debian, Fedora, Arch, etc.)
* **Compiler:** `gcc`
* **Privileges:** Root/Sudo authorization (required to interface with raw link-layer network adapters)

---

## 🚀 Compilation & Usage Guide

### 1. Identify Your Active Network Adapter
Before launching the sniffer, look for your active network interface name (e.g., `wlo1`, `eth0`, `usb0`):
```bash
ip a

gcc sniffer.c -o sniffer

sudo ./sniffer
```
Sample output if you include the commented printf statement:
```bash
[TCP] 192.168.1.5:43210 -> 142.250.190.46:443 [SYN ]
[TCP] 142.250.190.46:443 -> 192.168.1.5:43210 [SYN ACK ]

0000    47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a    GET / HTTP/1.1..
0010    48 6f 73 74 3a 20 65 78  61 6d 70 6c 65 2e 63 6f    Host: example.co
0020    6d 0d 0a 0d 0a                                      m....
```
This program is intended strictly for educational purposes, protocol analysis, and security research. Running a packet sniffer in promiscuous mode requires root permissions because it grants access to network analysis scopes. Always ensure you have explicit permission to audit the network environment you are testing.

Distributed under the MIT License. See LICENSE for more details.
