from scapy.all import *

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

class Sniffer:

    def __init__(self):
        self.p_types = {"ICMTP_ipv4": 1,"IGMTP": 2, "TCP": 6,"UDP": 17, "OSPF": 89, "ICMTP_ipv6": 58}
        self.iniciar_sniffer()

    def iniciar_sniffer(self):
        # try:
        sniff(prn = self.show_packts, store=1)
        # except Exception as e:
        #     print(e)
    
    def show_packts(self, packet):
        try:
            # print(packet.)
            # packet.show()
            infos = {}
            ether_frame = self.ethernet_frame(packet)
            # print(packet['Ethernet'].show())
            # print(packet['Ethernet'].type)
            # packet.show()

            # print('#### Ethernet frame ####')
            # print(ether_frame)

            ip_frame = self.ip_frame(ether_frame['ether_type'], packet)
            infos['IPv'] = ether_frame["ether_type"]
            infos['dest_mac'] = ether_frame['dest_mac']
            infos['dest_address'] = ip_frame['dest_address']
            infos['packet_size'] = len(packet)

            # print('\n#### IP frame ####')
            # print(ip_frame)
            # print(ether_frame['ether_type'])

            if(ip_frame['version'] == 4):
                next_layer = 'protocol'
                ip_version = 'IP'
            elif(ip_frame['version'] == 6):
                next_layer = 'next_header'
                ip_version = 'IPv6'
            else:
                return ''

            infos['transport_protocol'] = ip_frame[next_layer]

            print(infos)
            

            if(ip_frame[next_layer] == self.p_types['TCP']):
                tcp_header = self.tcp_header(packet[ip_version]['TCP'])
                # print('\n#### TCP Header ####')
                # print(tcp_header)
                pass
            elif(ip_frame[next_layer] == self.p_types['UDP']):
                udp_header = self.udp_header(packet[ip_version]['UDP'])
                # print('\n#### UDP Header ####')
                # print(udp_header)
                pass
            elif(ip_frame[next_layer] == self.p_types['ICMTP']):
                pass
            elif(ip_frame[next_layer] == self.p_types['IGMTP']):
                pass
            elif(ip_frame[next_layer] == self.p_types['OSPF']):
                pass
            # print(infos)

        except Exception as e:
            # print(e)
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
    sniffer = Sniffer()