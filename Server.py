import ipaddress
import json
import socket
import subprocess
import sys
import time
from datetime import datetime
from threading import Thread

import dhcppython as dhcppython


def load_configs():
    # Opening JSON file
    f = open('configs.json', )

    # returns JSON object as a dictionary
    data = json.load(f)

    # Iterating through the json list
    # for i in data['subnet']:
    #     print(i)

    global ip_range
    ip_range['from'] = data['range']['from']
    ip_range['to'] = data['range']['to']

    global ip_subnet
    ip_subnet['ip_block'] = data['subnet']['ip_block']
    ip_subnet['subnet_mask'] = data['subnet']['subnet_mask']

    global lease_time
    lease_time = data['lease_time']

    global reservation_list
    reservation_list = data['reservation_list']

    global black_list
    black_list = data['black_list']

    # Closing file
    f.close()


def get_pool_mode(pool, input_range, input_subnet):
    while True:
        choice = input("pool mode 1. Range or 2. Subnet ?\n > ")

        global pool_mode
        if choice == '1':
            pool_mode = "range"

            start = input_range['from'].split('.')[3]
            end = input_range['to'].split('.')[3]

            ip_str = input_range['to'].split('.')[0] + '.' + input_range['to'].split('.')[1] + '.' + \
                     input_range['to'].split('.')[2]

            for i in range(int(start), int(end) + 1):
                ip = ''
                ip = ip_str + '.' + str(i)
                # print(ip)
                pool[ip] = ''

        elif choice == '2':
            pool_mode = "subnet"
            print(input_subnet)
            start = 1
            end = 254 - int(input_subnet['subnet_mask'].split('.')[3])
            if end == 255:
                end = 254

            ip_str = input_subnet['ip_block'].split('.')[0] + '.' + input_subnet['ip_block'].split('.')[1] + '.' + \
                     input_subnet['ip_block'].split('.')[2]

            for i in range(int(start), int(end) + 1):
                ip = ''
                ip = ip_str + '.' + str(i)
                # print(ip)
                pool[ip] = ''

        else:
            print("wrong input! Try again.")
            continue
        break


# def respond_to_message(msg_type):
#     if msg_type == 'DHCPDISCOVER':
#         pass
#     if msg_type == 'DHCPREQUEST':
#         pass
#     pass


def send_offer(mac_address, xid):
    ip_address = ''
    # select ip from pool
    if mac_address in reservation_list.keys():
        ip_address = reservation_list[mac_address]
    elif mac_address in black_list:
        return 'BLOCKED'
    else:
        for ip in ip_pool.keys():
            if ip_pool[ip] == '':
                ip_address = ip
                break

    packet = dhcppython.packet.DHCPPacket.Offer(seconds=0, mac_addr=mac_address, tx_id=xid,
                                                yiaddr=ipaddress.IPv4Address(
                                                    ip_address))
    options = dhcppython.options.OptionList([dhcppython.options.options.short_value_to_object(53, "DHCPOFFER")])
    packet.options = options
    message = packet
    time.sleep(1)
    server.sendto(message.asbytes, ('localhost', 4422))
    print("OFFER sent!", flush=True)

    return ip_address


def send_ack(mac_address, xid, ip_address):
    packet = dhcppython.packet.DHCPPacket.Offer(seconds=0, mac_addr=mac_address, tx_id=xid,
                                                yiaddr=ipaddress.IPv4Address(
                                                    ip_address))
    options = dhcppython.options.OptionList([dhcppython.options.options.short_value_to_object(53, "DHCPACK")])
    packet.options = options
    message = packet
    time.sleep(1)
    # server.sendto(message.asbytes, ('localhost', 4422))
    server.sendto(message.asbytes, ('localhost', 4422))
    print("ACK sent!", flush=True)


def lease_time_handler(start_time, ip_set, ip, client_alive, mac_addr):
    while True:
        if ip_set and (time.time() - start_time) > lease_time:
            print('\nlease time exceed for client:', ip_pool[ip])

            print(ip, ': ip will be free from now.')
            clients_list.pop(ip_pool[ip])
            ip_pool[ip] = ''
            print('clients:', clients_list, '\n')

            ip_set = False
            client_threads[mac_addr] = False
            client_alive = False

            break


def client_handler(data, address):
    dhcp_packet = dhcppython.packet.DHCPPacket.from_bytes(data)

    message_type = dhcp_packet.msg_type
    xid = dhcp_packet.xid
    mac_address = dhcp_packet.chaddr

    # clients_list[mac_address] = ''

    suggested_ip = ''
    client_alive = True

    if message_type == 'DHCPDISCOVER':
        suggested_ip = send_offer(mac_address, xid)
        if suggested_ip == 'BLOCKED':
            print('This Client is in lack list!')
            client_alive = False
            client_threads[mac_address] = False

    while client_threads[mac_address]:
        start_time = 0
        ip_set = False

        data, address = server.recvfrom(1024)
        dhcp_packet = dhcppython.packet.DHCPPacket.from_bytes(data)
        message_type = dhcp_packet.msg_type
        print('Thread > new message received:', message_type)
        received_mac_address = dhcp_packet.chaddr

        # mac_address =
        # xid =
        if message_type == 'DHCPREQUEST' and received_mac_address == mac_address:
            # print('salam')
            time.sleep(1)

            if ip_pool[suggested_ip] == '' or ip_pool[suggested_ip] == mac_address:
                send_ack(mac_address, xid, suggested_ip)
                ip_pool[suggested_ip] = mac_address
                clients_list[mac_address] = suggested_ip
                print('clients:', clients_list, '\n')

                start_time = time.time()
                ip_set = True
                lease_thread = Thread(target=lease_time_handler,
                                      args=(start_time, ip_set, suggested_ip, client_alive, mac_address))
                lease_thread.start()
    #     print(client_alive)
    print("bbyeee")


def server_terminal_handler():
    while True:
        command = input()
        if command == 'sh clients' or 'show clients':
            print(clients_list)


def main():
    # Set a timeout so the socket does not block
    # indefinitely when trying to receive data.
    # server.settimeout(0.2)

    # server.bind(("", 4422))
    # terminal_handler = Thread(target=server_terminal_handler())
    # terminal_handler.start()

    while True:
        data, address = server.recvfrom(1024)
        dhcp_packet = dhcppython.packet.DHCPPacket.from_bytes(data)
        message_type = dhcp_packet.msg_type
        print('Server > New message Received:', message_type)
        if message_type == 'DHCPDISCOVER':
            client_thread = Thread(target=client_handler, args=(data, address))
            client_thread.start()

            mac_addr = dhcp_packet.chaddr
            client_threads[mac_addr] = True

            break


clients_list = {}

if __name__ == '__main__':
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    # Enable broadcasting mode
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    server.bind(("", 4421))
    # server.connect(('<broadcast>', 4422))

    pool_mode = ""

    ip_range = {}
    ip_subnet = {}
    lease_time = 0
    reservation_list = {}
    black_list = {}

    ip_pool = {}

    client_threads = {}

    load_configs()
    get_pool_mode(ip_pool, ip_range, ip_subnet)
    print(ip_pool)

    # sys.exit()
    main()
