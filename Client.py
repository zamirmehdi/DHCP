import math
import random
import socket
import time
from threading import Thread

import dhcppython

MAC_ADDRESS = '8C:8C:8C:8C:8C:8C'
ACK_TIMEOUT = 3
BACKOFF_CUTOFF = 120
INITIAL_INTERVAL = 10
LEASE_TIME = INITIAL_INTERVAL


def dhcp_discover():
    # message = b"your very important message"
    options = dhcppython.options.OptionList([dhcppython.options.options.short_value_to_object(53, "DHCPDISCOVER")])
    packet = dhcppython.packet.DHCPPacket.Discover(mac_addr=MAC_ADDRESS, seconds=0, tx_id=1234567890)
    packet.options = options

    message = packet
    client.sendto(message.asbytes, ("localhost", 4421))
    print("DISCOVER message sent!", flush=True)

    # time.sleep(1)


def dhcp_receive_offer(data):
    # data, addr = client.recvfrom(1024)
    # print("received message: %s" % data)
    # time.sleep(1)
    # print('salam')
    dhcp_packet = dhcppython.packet.DHCPPacket.from_bytes(data)
    message_type = dhcp_packet.msg_type

    xid = dhcp_packet.xid
    mac_address = dhcp_packet.chaddr
    ip_address = dhcp_packet.yiaddr

    # print(ip_address)
    # print(mac_address)
    # print(xid)
    # print(message_type)
    print('OFFER received:', ip_address)

    if my_ip_address == '':
        time.sleep(1)
        dhcp_request(xid, mac_address, ip_address)


def dhcp_request(xid, mac_address, ip_address):
    packet = dhcppython.packet.DHCPPacket.Discover(mac_addr=mac_address, seconds=0, tx_id=xid)
    options = dhcppython.options.OptionList([dhcppython.options.options.short_value_to_object(53, "DHCPREQUEST")])
    packet.options = options

    message = packet
    client.sendto(packet.asbytes, ('', 4421))

    global waiting_for_ack
    waiting_for_ack = True
    print("REQUEST message sent!", flush=True)


def dhcp_receive_ack(data):
    dhcp_packet = dhcppython.packet.DHCPPacket.from_bytes(data)
    message_type = dhcp_packet.msg_type

    xid = dhcp_packet.xid
    mac_address = dhcp_packet.chaddr
    ip_address = dhcp_packet.yiaddr

    # print(ip_address)
    # print(mac_address)
    # print(xid)
    # print(message_type)
    print('ACK received:', ip_address)

    global my_ip_address

    if mac_address == MAC_ADDRESS and my_ip_address == '':
        my_ip_address = ip_address
        global ip_discovered
        ip_discovered = True

    print("\nIP address set to \'{}\' successfully!".format(my_ip_address))

    global alive
    alive = False


def cal_timeout(prev_interval):
    # if prev_interval == INITIAL_INTERVAL:

    new_interval = (prev_interval * random.random())
    if new_interval < 1:
        new_interval += 1
    new_interval *= 2
    if new_interval >= BACKOFF_CUTOFF:
        new_interval = BACKOFF_CUTOFF

    return int(new_interval)


def timeout_handler(prev_interval):
    interval = prev_interval
    live = True
    while live:
        time_to_wait = interval
        print(time_to_wait)

        while time_to_wait > 0:
            time.sleep(1)
            time_to_wait -= 1

        if not ip_discovered:
            print("timeout exceed for ip DISCOVER!\n")
            interval = cal_timeout(interval)
            global alive
            alive = False
            client.sendto(b'', ('localhost', 4422))
        else:
            interval = prev_interval
            live = False


def lease_time_handler(start_time):
    while True:
        if (time.time() - start_time) > LEASE_TIME:
            print('\nlease time exceed! Discovering new IP...\n')
            global ip_discovered
            ip_discovered = False
            break


if __name__ == '__main__':

    my_ip_address = ''
    waiting_for_ack = False
    time_out = INITIAL_INTERVAL

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    # Enable broadcasting mode
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    client.bind(("", 4422))
    ip_discovered = False
    alive = True
    timer_on = False

    while True:

        while ip_discovered:
            continue

        if not timer_on:
            timeout_thread = Thread(target=timeout_handler, args=(time_out,))
            timeout_thread.start()
            timer_on = True

        dhcp_discover()
        alive = True

        # timeout_thread.start()

        while alive:

            data, addr = client.recvfrom(1024)
            if data == b'':
                break
            dhcp_packet = dhcppython.packet.DHCPPacket.from_bytes(data)
            message_type = dhcp_packet.msg_type
            if message_type == 'DHCPOFFER':
                dhcp_receive_offer(data)

            if message_type == 'DHCPACK' and waiting_for_ack:
                waiting_for_ack = False
                dhcp_receive_ack(data)

                timeout_thread.join()
                timer_on = False

                start_time = time.time()
                lease_thread = Thread(target=lease_time_handler, args=(start_time,))
                lease_thread.start()

        # break
