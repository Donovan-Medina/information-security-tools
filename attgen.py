#!/bin/env python3
"""
attgen.py made by Donovan Medina

Reads in files made from tcpdump and goes iteratively through each packet
printout the header information. Assignment 5 expands upon this and matches packets to a
config file -- looking for a victim ip and attacker's ip.

Dependencies:
    Python 3 (test machine used python 3.7)
    Scapy version 2.4.3

Usage:
    python pythonfile.py <filename> [optional flags]



TCP Flag info for scapy
    S = syn
    SA = syn-ack
    R = reset


"""

import sys
import os
import time
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.all import sendp, send, sr, checksum, srp1, srp


def check_usage():
    """
    Ensures the correct command line arguments passed.
    :returns: 0 if not sending over wire, 1 if sending over wire
    """
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print('Usage: {} [-s] <configuration file>'.format(sys.argv[0]), file=sys.stderr)
        exit(1)
    elif len(sys.argv) == 2:
        if sys.argv[1] == "-h" or sys.argv[1] == "--help":
            print("Usage: {} [-s] <configuration file>".format(sys.argv[0]))
            print("\t-h or --help to show this help message")
            print("\t-s is an optional flag used to indicate that the packets should be sent on the network.")
            exit(0)
        elif not os.path.isfile(sys.argv[1]):
            print('Error "{}" could not be found'.format(sys.argv[1]), file=sys.stderr)
            exit(1)
        else:
            return 0
    elif len(sys.argv) == 3:
        if sys.argv[1] != "-s":
            print('Error "{}" is not a valid flag'.format(sys.argv[1]), file=sys.stderr)
            exit(1)
        elif not os.path.isfile(sys.argv[2]):
            print('Error "{}" could not be found'.format(sys.argv[2]), file=sys.stderr)
            exit(1)
        else:
            return 1


def printout_packet_header(pkt_num, pkt_relative, pkt_local_time, pkt_actual_len, pkt_caplen):

    print('Packet {}'.format(pkt_num))
    print('{:.6f}'.format(pkt_relative))
    print('{}'.format(pkt_local_time))
    print('Captured Packet Length = {}'.format(pkt_caplen))
    print('Actual Packet Length = {}'.format(pkt_actual_len))


def printout_ether_header(eth_src, eth_dst, r_victim_info=0, r_attacker_info=0):
    print('Ethernet Header')
    print('\teth_src = {}'.format(eth_src))
    if r_attacker_info != 0:
        print('\trep_src = {}'.format(r_attacker_info[1]))
    print('\teth_dst = {}'.format(eth_dst))
    if r_victim_info != 0:
    	print('\trep_dst = {}'.format(r_victim_info[1]))


def printout_ip_header(ip_pkt, r_victim_info=0, r_attacker_info=0):
    print('\tIP')
    print('\t\tip_len = {}'.format(ip_pkt.fields["len"]))
    print('\t\tip_src = {}'.format(ip_pkt.fields["src"]))
    if r_attacker_info != 0:
        print('\t\trep src = {}'.format(r_attacker_info[0]))
    print('\t\tip_dst = {}'.format(ip_pkt.fields["dst"]))
    if r_victim_info != 0:
        print('\t\trep dst = {}'.format(r_victim_info[0]))
    if r_attacker_info != 0 and r_victim_info != 0:
        printout_ip_type(ip_pkt, r_victim_info[2], r_attacker_info[2])
    else:
        printout_ip_type(ip_pkt)

def printout_ip_type(ip_pkt, r_dst=0, r_src=0):
    common_protos = {
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        17: "UDP"
    }
    ICMP_types = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        4: "Source Quench",
        5: "Redirect",
        6: "Alternate Host Address",
        8: "Echo",
        9: "Router Advertisement",
        10: "Router Selection",
        11: "Time Exceeded",
        12: "Bad IP header",
        13: "Timestamp",
        14: "Timestamp Reply",
        15: "Information Request",
        16: "Information Reply",
        30: "Traceroute",
        31: "Datagram Conversion Error",
        32: "Mobile Host Redirect",
        33: "IPv6 Where-Are-You",
        34: "IPv6 I-Am-Here",
        35: "Mobile Registration Request",
        36: "Mobile Registration Reply",
        37: "Domain Name Request",
        38: "Domain Name Reply",
        39: "SKIP",
        40: "Photuris"

    }
    if ip_pkt.fields["proto"] in common_protos:
        proto = common_protos[ip_pkt.fields["proto"]]
        print('\t\t\t{}'.format(proto))
        if proto == "TCP":
            tcp_pkt = ip_pkt[TCP]
            print('\t\t\t\tSrc Port = {}'.format(tcp_pkt.fields["sport"]))
            if r_src != 0:
                print('\t\t\t\tRep src Port = {}'.format(r_src))
            print('\t\t\t\tDst Port = {}'.format(tcp_pkt.fields["dport"]))
            if r_dst != 0:
                print('\t\t\t\tRep dst Port = {}'.format(r_dst))
            print('\t\t\t\tSeq = {}'.format(tcp_pkt.fields["seq"]))
            print('\t\t\t\tAck = {}'.format(tcp_pkt.fields["ack"]))
        elif proto == "ICMP":
            ICMP_pkt = ip_pkt[ICMP]
            if ICMP_pkt.fields["type"] in ICMP_types:
                print('\t\t\t\t{}'.format(ICMP_types[ICMP_pkt.fields["type"]]))
            else:
                print("\t\t\t\tOther")
        elif proto == "UDP":
            udp_pkt = ip_pkt[UDP]
            print('\t\t\t\tSrc Port = {}'.format(udp_pkt.fields["sport"]))
            print('\t\t\t\tDst Port = {}'.format(udp_pkt.fields["dport"]))
    else:
        print("\t\t\tOTHER")


def open_config(filename):
    """
    open_config()
    :parameter: takes in a config file that was made specifically for link level injection for attack replay generator
    :returns:
        - tcpdump_log_file <string>
        - victim_info <list> [0 = ip, 1 = mac, 2 = port]
        - attacker_info <list> [0 = ip, 1 = mac, 2 = port]
        - r_victim_info <list> [0 = ip, 1 = mac, 2 = port]
        - r_attacker_info <list> [0 = ip, 1 = mac, 2 = port]
        - interface <string>
        - timing_type <string>
    """
    # vars to safe into
    tcpdump_log = None
    victim_info = []
    attacker_info = []
    r_victim_info = []
    r_attacker_info = []
    interface = None
    timing_type = None
    
    with open(filename) as config_file:
        line_cnt = 0
        for line in config_file:
            if line_cnt == 0:
                tcpdump_log = line.strip()  # tcpdump log file name
                if "/" in filename:
                    tokens = filename.split("/")
                    tcpdump_log = tokens[0] + "/" + tcpdump_log
                if not os.path.isfile(tcpdump_log):
                    print('Error: "{}" could not be found'.format(tcpdump_log), file=sys.stderr)
                    exit(-1)
            if line_cnt == 1:
                victim_info.append(line.strip())  # victim ip
            if line_cnt == 2:
                victim_info.append(line.strip())  # victim mac
            if line_cnt == 3:
                victim_info.append(int(line.strip()))  # victim port
            if line_cnt == 4:
                attacker_info.append(line.strip())  # attacker ip
            if line_cnt == 5:
                attacker_info.append(line.strip())  # attacker mac
            if line_cnt == 6:
                attacker_info.append(int(line.strip()))  # attacker port
            if line_cnt == 7:
                r_victim_info.append(line.strip())  # replay victim ip
            if line_cnt == 8:
                r_victim_info.append(line.strip())  # replay victim mac
            if line_cnt == 9:
                r_victim_info.append(int(line.strip()))  # replay victim port
            if line_cnt == 10:
                r_attacker_info.append(line.strip())  # replay attacker ip
            if line_cnt == 11:
                r_attacker_info.append(line.strip())  # replay attacker mac
            if line_cnt == 12:
                r_attacker_info.append(int(line.strip()))  # replay attacker port
            if line_cnt == 13:
                timing_type = line.strip()  # interface
            if line_cnt == 14:
                timing_type = line.strip()  # timing type
                print(timing_type)
                if timing_type != "continuous" and timing_type != "delay":
                    print("Error, configuration file not setup correctly.", file=sys.stderr)
                    exit(-1)
            line_cnt += 1

    return tcpdump_log, victim_info, attacker_info, r_victim_info, r_attacker_info, interface, timing_type


def open_logfile(logfile, victim_info, attacker_info, r_victim_info, r_attacker_info, interface, timing_type,
                 s_switch=None):

    print('Opening "{}"'.format(logfile))

    # before reading through packets we must get some info about the file header
    fp = open(logfile, 'rb')
    magic_number = fp.read(4).hex()
    major_version = int.from_bytes(fp.read(2), byteorder="little")
    minor_version = int.from_bytes(fp.read(2), byteorder="little")
    time_zone_offset = int.from_bytes(fp.read(4), byteorder="little")
    time_stamp_acc = int.from_bytes(fp.read(4), byteorder="little")
    snapshot_len = int.from_bytes(fp.read(4), byteorder="little")
    link_layer_type = int.from_bytes(fp.read(4), byteorder="little")
    fp.close()
    print('PCAP Magic')
    print('Version major number = {}'.format(major_version))
    print('Version minor number = {}'.format(minor_version))
    print('GMT to local correction = {}'.format(time_zone_offset))
    print('Timestamp accuracy = {}'.format(time_stamp_acc))
    print('Snaplen = {}'.format(snapshot_len))
    print('Linktype = {}\n'.format(link_layer_type))

    # list of common internet protocol numbers we will use
    ip_proto_list = {
        "ICMP": 1,
        "IGMP": 2,
        "TCP": 6,
        "UDP": 17
    }

    frame_num = 0
    relative_start_time = 0
    flagged_packets = 0
    sent_packets = 0
    new_seq = 0
    new_ack = 0
    amount_recv = 0
    set_flag = None
    # open file for reading packets
    for (pkt_data, pkt_metadata,) in RawPcapReader(logfile):

        # getting packet info and timestamp
        pkt_num = frame_num
        pkt_time_sec = pkt_metadata[0]
        pkt_time_usec = pkt_metadata[1]
        local_time = time.asctime(time.localtime(pkt_time_sec))
        pkt_actual_len = pkt_metadata[2]
        pkt_caplen = pkt_metadata[3]
        total_time = pkt_time_sec + (pkt_time_usec / 100000)
        if pkt_num == 0:
            relative_start_time = total_time
            pkt_relative_time = 0000.000000
        else:
            pkt_relative_time = total_time - relative_start_time

        # ethernet header info acquired
        ether_pkt = Ether(pkt_data)
        eth_src = ether_pkt.fields["src"]
        eth_dst = ether_pkt.fields["dst"]
        if 'type' not in ether_pkt.fields:
            frame_num += 1
            continue
        # ensuring it is ipv4
        if ether_pkt.type != 0x0800:
            frame_num += 1
            continue

        # getting ip info [TCP vs UPD vs ICMP etc]
        ip_pkt = ether_pkt[IP]

        # check if the packet is the one we want based on the config file
        if ip_pkt.fields["dst"] == victim_info[0]:
            flagged_packets += 1
            printout_packet_header(pkt_num, pkt_relative_time, local_time, pkt_actual_len, pkt_caplen)
            printout_ether_header(eth_src, eth_dst, r_victim_info, r_attacker_info)
            printout_ip_header(ip_pkt, r_victim_info, r_attacker_info)
		
            # replace the original information for sending
            if s_switch is None:
                print("\t\tPacket is not sent")
            else:
                ether_pkt[Ether].src = r_attacker_info[1]
                ether_pkt[Ether].dst = r_victim_info[1]
                ether_pkt[IP].fields["src"] = r_attacker_info[0]
                ether_pkt[IP].fields["dst"] = r_victim_info[0]
                ether_pkt[IP][TCP].fields["sport"] = r_attacker_info[2]
                ether_pkt[IP][TCP].fields["dport"] = r_victim_info[2]

                # fix ack and seq numbers
                ether_pkt[TCP].seq = new_seq
                ether_pkt[TCP].ack = new_ack
                print("\t\tsending pkt seq: {} ack: {}".format(ether_pkt[TCP].seq, ether_pkt[TCP].ack))
                if set_flag is not None:
                    ether_pkt[TCP].flags = set_flag

                # redo checksum
                del ether_pkt.chksum
                del ether_pkt[IP].chksum
                del ether_pkt[IP][TCP].chksum
                ether_pkt = ether_pkt.__class__(bytes(ether_pkt))
                
                if timing_type == "delay":
                    time.sleep(.5)  # sleep for 500 ms

                # send packet and receive
                answer = srp1(ether_pkt, iface=interface, verbose=False, inter=1, timeout=2)
                sent_packets += 1
                print("\t\tPacket sent with flag: {}".format(ether_pkt[TCP].flags))
                if answer != None:
                    amount_recv += 1
                    print("\t\trecieved packet with flag: {}".format(answer[TCP].flags))
                    print("\t\ttheir seq: {} , ack: {}".format(answer[TCP].seq, answer[TCP].ack))
                    print("\t\tsize of TCP payload: {}".format(len(ether_pkt[TCP].payload)))

                    if "A" ==  answer[TCP].flags:
                        print("\t\tvictim acknowledge data was sent, send more")
                        new_seq = answer[TCP].ack
                        new_ack = answer[TCP].seq + len(answer[TCP].payload)
                        print("\t\t\t\tnew seq = {} \tnew ack = {}".format(new_seq, new_ack))

                    elif "PA" == answer[TCP].flags:
                        print("\t\tVictim sent data to us")
                        new_seq = answer[TCP].ack
                        new_ack = answer[TCP].seq + len(answer[TCP].payload)
                        print("\t\t\t\tnew seq = {} \tnew ack = {}".format(new_seq, new_ack))

                    elif "SA" == answer[TCP].flags:
                        print("\t\tvictim sent a syn ack, so we'll respond with an ack")
                        new_seq = answer[TCP].ack
                        new_ack = answer[TCP].seq + 1
                        print("\t\t\t\tnew seq = {} \tnew ack = {}".format(new_seq, new_ack))

                    elif "F" ==  answer[TCP].flags:
                        print("\t\tgot a fin flag -- send one back...")
                        new_seq = answer[TCP].ack
                        new_ack = answer[TCP].seq + 1
                        set_flag = "F"
                    else:
                        print("\t\tdid not recieve a packet yet from victim")
        else:
            # regular print out since it did not match      
            printout_packet_header(pkt_num, pkt_relative_time, local_time, pkt_actual_len, pkt_caplen)
            printout_ether_header(eth_src, eth_dst)
            printout_ip_header(ip_pkt)
            print("\t\tPacket is not sent")

        frame_num += 1

    print('\n{} contains {} total packets ({} flagged) ({} sent) ({} recieved)'.format(logfile, frame_num, flagged_packets, sent_packets, amount_recv))

def main():
    # checks usage of command line and if the user wants to send over the wire
    s_type = check_usage()

    # opens the config file and formats the data in them into lists and vars, then uses open logfile
    if s_type == 0:
        tcpdump_log, victim_info, attacker_info, r_victim_info, r_attacker_info, interface, timing_type \
            = open_config(sys.argv[1])
        open_logfile(tcpdump_log, victim_info, attacker_info, r_victim_info, r_attacker_info, interface, timing_type)
    if s_type == 1:
        tcpdump_log, victim_info, attacker_info, r_victim_info, r_attacker_info, interface, timing_type \
            = open_config(sys.argv[2])
        open_logfile(tcpdump_log, victim_info, attacker_info, r_victim_info, r_attacker_info, interface,
                     timing_type, "enabled")


if __name__ == '__main__':
    main()
