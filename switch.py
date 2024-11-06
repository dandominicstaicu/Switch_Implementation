#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
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
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def remove_vlan_tag(data):
    data_without_vlan = data[0:12] + data[16:]
    return data_without_vlan

def send_bdpu_every_sec():
    while True:
        # TODO Send BDPU every second if necessary
        time.sleep(1)

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
            print("Error reading switch configuration file {config_file}: {e}")
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

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        # dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        # src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # TODO: Implement forwarding with learning
        # TODO: Implement VLAN support

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
                if i == interface:
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
                if out_interface != interface:
                    outgoing_interface_config = interface_config[out_interface]
                    if outgoing_interface_config['mode'] == 'access':
                        data_to_send = remove_vlan_tag(data)
                        send_to_link(out_interface, length - 4, data_to_send)
                    elif outgoing_interface_config['mode'] == 'trunk':
                        send_to_link(out_interface, length, data)
            else:
                # Flood the frame
                for i in interfaces:
                    if i == interface:
                        continue
                    outgoing_interface_config = interface_config[i]
                    if outgoing_interface_config['mode'] == 'access':
                        if outgoing_interface_config['vlan'] != vlan_id:
                            continue
                        data_to_send = remove_vlan_tag(data)
                        send_to_link(i, length - 4, data_to_send)
                    elif outgoing_interface_config['mode'] == 'trunk':
                        send_to_link(i, length, data)


        

        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()