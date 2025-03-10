Dan-Dominic Staicu 331CA 2024

Tasks: 1, 2, 3

# Simplified Switch Implementation with VLAN and STP Support

This project implements a simulated Ethernet switch with a Content Addressable Memory (CAM) table, VLAN (Virtual Local Area Network) tagging, and a simplified version of the Spanning Tree Protocol (STP) to prevent network loops. The switch is capable of dynamically learning MAC addresses, managing VLAN tags, and handling STP frames to build a loop-free network topology.

## Overview

This switch implements several key networking functions:
- **CAM Table (MAC Address Table)**: Tracks MAC addresses to forward frames efficiently.
- **VLAN Support**: Segregates network traffic by tagging frames with VLAN IDs.
- **Spanning Tree Protocol (STP)**: Prevents loops by blocking certain ports and selecting a root bridge in the network.

## Components

### 1. CAM Table
The CAM table allows the switch to learn which MAC addresses are reachable on each port. This is implemented using a dictionary where the keys are (MAC address, VLAN ID) pairs, and the values are the port numbers. When a frame is received, the source MAC address is stored with the receiving port, allowing the switch to learn the network topology dynamically.

- **Learning MAC Addresses**: When a frame is received, the source MAC and VLAN ID are added to the table.
- **Forwarding Frames**: For unicast frames, the table is checked for the destination MAC. If known, the frame is forwarded to the corresponding port; otherwise, it is flooded across all ports in the same VLAN.

### 2. VLAN Support
The switch supports VLANs to logically separate traffic within the network. VLAN support includes adding 802.1Q tags to frames traversing trunk ports and removing tags when forwarding to access ports.

- **VLAN Tagging**: On access ports, frames are tagged with the VLAN ID specific to that port. On trunk ports, incoming frames with VLAN tags are processed based on their VLAN IDs.
- **Access and Trunk Port Behavior**: Access ports are tied to a specific VLAN, while trunk ports allow multiple VLANs, carrying traffic tagged with different VLAN IDs. Frames are only forwarded to ports within the same VLAN.

### 3. Spanning Tree Protocol (STP)
To prevent loops in the network, this switch uses a simplified version of the IEEE 802.1D STP. The protocol elects a root bridge, calculates the shortest path to it, and blocks redundant paths to ensure a loop-free topology.

- **BPDU (Bridge Protocol Data Unit) Creation**: The switch generates BPDU packets containing information about the root bridge, path cost, and sender bridge ID. BPDUs are sent periodically on trunk ports to maintain the spanning tree structure.
- **Root Bridge Election**: The switch determines whether it is the root bridge based on bridge priority (configured through a file). If it detects a better root bridge through received BPDUs, it updates its root bridge, root path cost, and blocks redundant paths.
- **Port Blocking**: STP selectively blocks ports to break loops. For each port, the switch decides whether it should be forwarding or blocking based on the best-known path to the root bridge.

### 4. Frame Parsing and Handling
Ethernet frames are parsed to extract MAC addresses, EtherType, and VLAN ID (if tagged). The switch differentiates between unicast, multicast, and broadcast frames to handle each appropriately.

- **Broadcast and Multicast Handling**: Broadcast frames and certain multicast frames (such as STP BPDUs) are forwarded to all ports within the same VLAN.
- **Unicast Forwarding**: The switch forwards unicast frames based on the CAM table. If the destination MAC is unknown, the frame is flooded across eligible ports.

## How It Works

1. **Configuration**: The switch reads its configuration file to determine its priority and port modes (access/trunk). Each access port is assigned a VLAN ID.
2. **MAC Learning and Forwarding**: The switch learns MAC addresses from incoming frames and updates the CAM table. It uses this table to forward frames directly to the correct port, minimizing unnecessary traffic.
3. **VLAN Management**: Frames are tagged or untagged depending on the port type. Trunk ports carry VLAN-tagged frames, while access ports are limited to their assigned VLAN.
4. **Spanning Tree Protocol**: BPDUs are generated and processed to establish a loop-free topology. The switch continually updates its view of the network, blocking and unblocking ports as necessary based on received BPDUs.
5. **Periodic BPDU Sending**: A background thread sends BPDUs periodically, ensuring other switches recognize the root bridge and maintain an up-to-date spanning tree.

### Scheleton for the Hub implementation.

## Running

```bash
sudo python3 checker/topo.py
```

This will open 9 terminals, 6 hosts and 3 for the switches. On the switch terminal you will run 

```bash
make run_switch SWITCH_ID=X # X is 0,1 or 2
```

The hosts have the following IP addresses.
```
host0 192.168.1.1
host1 192.168.1.2
host2 192.168.1.3
host3 192.168.1.4
host4 192.168.1.5
host5 192.168.1.6
```

We will be testing using the ICMP. For example, from host0 we will run:

```
ping 192.168.1.2
```

Note: We will use wireshark for debugging. From any terminal you can run `wireshark&`.
