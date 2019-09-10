from scapy.all import *

# Protocol values
#     1 - ICMTP
#     2 - IGMTP
#     6 - TCP
#     17 - UDP
#     89 - OSPF

class Sniffer:

    def __init__(self):
        self.p_types = {"ICMTP": 1,"IGMTP": 2, "TCP": 6,"UDP": 17, "OSPF": 89}
        self.iniciar_sniffer()

    def iniciar_sniffer(self):
        try:
            sniff(prn = self.show_packts, store=1)
        except Exception as e:
            print(e)
    
    def show_packts(self, packet):
        ether_frame = self.ethernet_frame(packet)
        ip_frame = self.ip_frame(ether_frame['ether_type'], packet)

        if(ip_frame['version'] == 4):
            next_layer = 'protocol'
            ip_version = 'IP'
        elif(ip_frame['version'] == 6):
            next_layer = 'next_header'
            ip_version = 'IPv6'
        else:
            return ''

        if(ip_frame[next_layer] == self.p_types['TCP']):
            tcp_header = self.tcp_header(packet[ip_version]['TCP'])
            pass
        elif(ip_frame[next_layer] == self.p_types['UDP']):
            udp_header = self.udp_header(packet[ip_version]['UDP'])
            print(udp_header)
            pass
        elif(ip_frame[next_layer] == self.p_types['ICMTP']):
            pass
        elif(ip_frame[next_layer] == self.p_types['IGMTP']):
            pass
        elif(ip_frame[next_layer] == self.p_types['OSPF']):
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
                "dest_addres": frame.dst            
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