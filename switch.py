#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def is_broadcast(mac_address):
    return mac_address == b'\xff\xff\xff\xff\xff\xff'

def is_multicast(mac_address):
    # Multicast addresses have the least significant bit of the first octet set to 1
    return (mac_address[0] & 1) == 1 and not is_broadcast(mac_address)

def is_unicast(mac_address):
    # Unicast addresses have the least significant bit of the first octet set to 0
    return (mac_address[0] & 1) == 0

def create_vlan_tag(vlan_id):
    # 0x8200 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def remove_vlan_tag(data):
    data_without_vlan = data[0:12] + data[16:]
    return data_without_vlan

def compute_BPDU_package(port, age, own_bridge_ID, root_bridge_ID, root_path_cost):
    # Build BPDU message according to IEEE 802.1D
    mac_address_str = '01:80:c2:00:00:00'
    dest_mac = bytes([int(x, 16) for x in mac_address_str.split(':')])
    src_mac = get_switch_mac()
    ethertype = b'\x00\x00'  # Length field set to zero for LLC
    # LLC Header
    llc_header = b'\x42\x42\x03'
    # STP Payload   
    protocol_id = b'\x00\x00'
    version = b'\x00'
    bpdu_type = b'\x00'
    flags = b'\x00'
    # Build BPDU message
    data = dest_mac + src_mac + ethertype + llc_header + protocol_id + version + bpdu_type + flags
    data += root_bridge_ID.to_bytes(8, 'big') + root_path_cost.to_bytes(4, 'big') + own_bridge_ID.to_bytes(8, 'big')
    port_id = b'\x80\x04'  # Example port ID
    message_age = age.to_bytes(2, 'big')
    max_age = (20).to_bytes(2, 'big')
    hello_time = (2).to_bytes(2, 'big')
    forward_delay = (15).to_bytes(2, 'big')
    data += port_id + message_age + max_age + hello_time + forward_delay
    return data

def send_bdpu_every_sec(interfaces, port_state, interface_config, own_bridge_ID, root_bridge_ID, root_path_cost):
    while True:
        if own_bridge_ID == root_bridge_ID:
            for port in interfaces:
                if interface_config[port]['mode'] == 'trunk' and port_state[port] == 1:
                    data = compute_BPDU_package(port, 0, own_bridge_ID, root_bridge_ID, root_path_cost)
                    send_to_link(port, len(data), data)
        time.sleep(1)

def bdpu_parse(data):
    # Parse BPDU message
    root_bridge_ID = int.from_bytes(data[22:30], byteorder='big')
    root_path_cost = int.from_bytes(data[30:34], byteorder='big')
    sender_bridge_ID = int.from_bytes(data[34:42], byteorder='big')
    return root_bridge_ID, root_path_cost, sender_bridge_ID

def run_stp(data, interface, own_bridge_ID, root_bridge_ID, root_path_cost, root_port, port_state, interfaces, interface_config):
    bdpu_root_bridge, bdpu_path_cost, bdpu_sender_bridge = bdpu_parse(data)
    bdpu_path_cost += 10  # Assuming cost of 10 for the link
    if bdpu_root_bridge < root_bridge_ID:
        initial_root_bridge = root_bridge_ID
        root_bridge_ID = bdpu_root_bridge
        root_path_cost = bdpu_path_cost
        root_port = interface

        if initial_root_bridge == own_bridge_ID:
            for port in interfaces:
                if interface_config[port]['mode'] == 'trunk':
                    if port != interface:
                        port_state[port] = 0
        port_state[interface] = 1

        for port in interfaces:
            if interface_config[port]['mode'] == 'trunk':
                if port != interface and port_state[port] == 1:
                    data = compute_BPDU_package(port, 0, own_bridge_ID, root_bridge_ID, root_path_cost)
                    send_to_link(port, len(data), data)
    elif bdpu_root_bridge == root_bridge_ID:
        if interface == root_port and bdpu_path_cost < root_path_cost:
            root_path_cost = bdpu_path_cost
        elif interface != root_port:
            if bdpu_path_cost > root_path_cost:
                port_state[interface] = 1
    elif bdpu_sender_bridge == own_bridge_ID:
        port_state[interface] = 0

    if own_bridge_ID == root_bridge_ID:
        for port in interfaces:
            if interface_config[port]['mode'] == 'trunk':
                port_state[port] = 1

    return root_bridge_ID, root_path_cost, root_port

def read_switch_config(id):
    config_file = f'./configs/switch{id}.cfg'
    print(config_file)
    port_config = {}
    switch_priority = None

    try:
        with open(config_file, 'r') as f:
            lines = f.readlines()
            switch_priority = int(lines[0].strip())
            for line in lines[1:]:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                tokens = line.split()
                interface_name = tokens[0]
                if len(tokens) < 2:
                    continue
                if tokens[1] == 'T':
                    port_config[interface_name] = {'mode' : 'trunk'}
                else:
                    vlan_id = int(tokens[1])
                    port_config[interface_name] = {'mode': 'access', 'vlan': vlan_id}
    except Exception as e:
        print(f"Error reading switch configuration file {config_file}: {e}")
    return switch_priority, port_config

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    mac_table = {}

    switch_priority, port_config = read_switch_config(switch_id)

    interface_name_to_number = {}
    interface_number_to_name = {}

    for i in interfaces:
        interface_name = get_interface_name(i)
        interface_number_to_name[i] = interface_name
        interface_name_to_number[interface_name] = i

    interface_config = {}
    for i in interfaces:
        interface_name = interface_number_to_name[i]
        if interface_name in port_config:
            interface_config[i] = port_config[interface_name]
        else:
            interface_config[i] = {'mode': 'access', 'vlan': 1}

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Initialize STP variables
    port_state = {}
    own_bridge_ID = switch_priority
    root_bridge_ID = own_bridge_ID
    root_path_cost = 0
    root_port = None

    # Initialize port states
    for i in interfaces:
        if interface_config[i]['mode'] == 'trunk':
            port_state[i] = 0  # Blocked
        else:
            port_state[i] = 1  # Forwarding

    if own_bridge_ID == root_bridge_ID:
        for port in interfaces:
            port_state[port] = 1  # Set all ports to forwarding

    # Create and start a new thread that deals with sending BPDU
    t = threading.Thread(target=send_bdpu_every_sec, args=(interfaces, port_state, interface_config, own_bridge_ID, root_bridge_ID, root_path_cost))
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Receive frames
        interface, data, length = recv_from_any_link()

        # Check if port is blocked
        if port_state[interface] == 0:
            continue

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')
        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # Check if BPDU packet
        if dest_mac == b'\x01\x80\xc2\x00\x00\x00':
            root_bridge_ID, root_path_cost, root_port = run_stp(
                data, interface, own_bridge_ID, root_bridge_ID,
                root_path_cost, root_port, port_state, interfaces, interface_config)
            continue

        # Decide how to forward the frame
        incoming_interface_config = interface_config[interface]
        if incoming_interface_config['mode'] == 'access':
            # Access port, add VLAN tag
            port_vlan_id = incoming_interface_config['vlan']
            vlan_id = port_vlan_id
            vlan_tag = create_vlan_tag(vlan_id)
            data = data[0:12] + vlan_tag + data[12:]
            length += 4
        elif incoming_interface_config['mode'] == 'trunk':
            if vlan_id == -1:
                print(f"Error: Received untagged frame on trunk port {interface}", file=sys.stderr)
                continue
            # VLAN ID is extracted
        else:
            print(f"Error: Unknown port mode on interface {interface}", file=sys.stderr)
            continue

        mac_table[(src_mac, vlan_id)] = interface

        # Forwarding logic
        if is_broadcast(dest_mac) or is_multicast(dest_mac):
            for i in interfaces:
                if i == interface or port_state[i] == 0:
                    continue
                outgoing_interface_config = interface_config[i]
                if outgoing_interface_config['mode'] == 'access':
                    if outgoing_interface_config['vlan'] != vlan_id:
                        continue
                    data_to_send = remove_vlan_tag(data)
                    send_to_link(i, length - 4, data_to_send)
                elif outgoing_interface_config['mode'] == 'trunk':
                    send_to_link(i, length, data)
        else:
            key = (dest_mac, vlan_id)
            if key in mac_table:
                out_interface = mac_table[key]
                if out_interface != interface and port_state[out_interface] == 1:
                    outgoing_interface_config = interface_config[out_interface]
                    if outgoing_interface_config['mode'] == 'access':
                        data_to_send = remove_vlan_tag(data)
                        send_to_link(out_interface, length - 4, data_to_send)
                    elif outgoing_interface_config['mode'] == 'trunk':
                        send_to_link(out_interface, length, data)
            else:
                # Flood the frame
                for i in interfaces:
                    if i == interface or port_state[i] == 0:
                        continue
                    outgoing_interface_config = interface_config[i]
                    if outgoing_interface_config['mode'] == 'access':
                        if outgoing_interface_config['vlan'] != vlan_id:
                            continue
                        data_to_send = remove_vlan_tag(data)
                        send_to_link(i, length - 4, data_to_send)
                    elif outgoing_interface_config['mode'] == 'trunk':
                        send_to_link(i, length, data)

if __name__ == "__main__":
    main()
