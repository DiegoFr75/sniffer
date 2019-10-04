from scapy.all import *
from datetime import datetime
import pandas as pd
import os

# Protocol values
#     1 - ICMTP
#     2 - IGMTP
#     6 - TCP
#     17 - UDP
#     89 - OSPF

# Ip frama protocol types
# 1 - ICMP IPv4
# 58 - ICMP IPv6
# 6 - TCP
# 17 - UDP
FILE_PATH = 'data.csv'

class Sniffer:

    def __init__(self):
        self.p_types = {"ICMTP_ipv4": 1,"IGMTP": 2, "TCP": 6,"UDP": 17, "OSPF": 89, "ICMTP_ipv6": 58}
        self.iniciar_sniffer()

    def iniciar_sniffer(self):
        try:
            sniff(prn = self.save_packets, store=1)
        except Exception as e:
            print(e)
    
    def save_packets(self, packet):
        try:
            infos = {'IPv': None, 'source_address': None, 'dest_address': None, 'transport_protocol': None, 'packet_size': None, 'timestamp': None}
            ether_frame = self.ethernet_frame(packet)
            ip_frame = self.ip_frame(ether_frame['ether_type'], packet)
            infos['dest_address'] = ip_frame['dest_address']
            infos['source_address'] = ip_frame['source_address']
            infos['packet_size'] = len(packet)

            if not (ether_frame['ether_type'] == 0x806):
                infos['IPv'] = ip_frame['version']
                if(ip_frame['version'] == 4):
                    infos['transport_protocol'] = ip_frame['protocol']
                elif(ip_frame['version'] == 6):
                    infos['transport_protocol'] = ip_frame['next_header']
                else:
                    return ''

            else :
                ip_version = ip_frame['ARP'].ptype
                if ip_version == 0x86dd:
                    infos['IPv'] = 6
                else:
                    infos['IPv'] = 4
            

            
            now = datetime.now()
            infos['timestamp'] = datetime.timestamp(now)

            dataFrame = pd.DataFrame.from_dict(infos, orient='index').T
            # print(dataFrame)
            dataFrame.to_csv(FILE_PATH, mode='a', header=False, index = False)
        

        except Exception as e:
            print(e)
            print(ether_frame['ether_type'])
            pass
        

    def ethernet_frame(self, packet):
        return {
            "source_mac": packet.src,
            "dest_mac": packet.dst,
            "ether_type": hex(packet.type)
        }

    def ip_frame(self, ether_type, packet):
        if(ether_type == '0x86dd'):
            frame = packet['IPv6']
            return {
                "version": frame.version,
                "trafic_class": frame.tc,
                "flow_label": frame.fl,
                "payload_lenght": frame.plen,
                "next_header": frame.nh,
                "hop_limit": frame.hlim,
                "source_address": frame.src,
                "dest_address": frame.dst            
            }
        elif(ether_type ==  '0x800'):
            frame = packet['IP']
            return {
                "version": frame.version,
                "header_lenght": frame.ihl,
                "type_of_service": frame.tos,
                "total_lengh": frame.len,
                "identification": frame.id,
                "flags": frame.flags,
                "frag_offset": frame.frag,
                "ttl": frame.ttl,
                "protocol": frame.proto,
                "header_checksum": frame.chksum,
                "source_address": frame.src,
                "dest_address": frame.dst
            }

    def tcp_header(self, packet):
        return {
                "source_port": packet.sport,
                "dest_port": packet.dport,
                "sequence_number": packet.seq,
                "ack_number": packet.ack,
                "data_ofs": packet.dataofs,
                "reserved": packet.reserved,
                "flags": packet.flags,
                "window": packet.window,
                "checksum": packet.chksum,
                "urgent_pointer": packet.urgptr,
                "options": packet.options,
        }

    def udp_header(self, packet):
        return {
            "source_port": packet.sport,
            "dest_port": packet.dport,
            "lenght": packet.len,
            "checksum": packet.chksum
        }


if __name__ == "__main__":
    columns_names = ['IPv', 'source_address', 'dest_address', 'transport_protocol', 'packet_size', 'timestamp']
    dataFrame = pd.DataFrame(columns_names).T

    if not os.path.isfile(FILE_PATH):
        dataFrame.to_csv(FILE_PATH, header = False, index=False)

    sniffer = Sniffer()