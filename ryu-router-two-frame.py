# AEM: 2980
# Name: Roumpos Ioannis

# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Two OpenFlow 1.0 L3 Static Routers and two OpenFlow 1.0 L2 learning switches.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import inet
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import udp
from ryu.lib.packet import ether_types

"""
fill in the code here (optional)
"""
ARP_TABLE = {
    '192.168.1.2': '00:00:00:00:01:02',
    '192.168.1.3': '00:00:00:00:01:03',
    '192.168.2.2': '00:00:00:00:02:02',
    '192.168.2.3': '00:00:00:00:02:03'
}

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.offset = 0
        # Port pool to get a random port
        # self.port_counter = -1
        # self.ports_pool = list(range(5000, 65563))

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        
        if dpid == 0x1A:
            actions = [
                datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:05:02"),
                datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:05:01"),
                datapath.ofproto_parser.OFPActionOutput(4)
            ]
            
            match = datapath.ofproto_parser.OFPMatch(
                dl_type = ether_types.ETH_TYPE_IP,
                nw_tos = 8,
                nw_dst = '192.168.2'
            )
            self.add_flow(datapath, match, actions)
        
        elif dpid == 0x1B:
            
            actions = [
                datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:05:01"),
                datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:05:02"),
                datapath.ofproto_parser.OFPActionOutput(4)
            ]
            
            match = datapath.ofproto_parser.OFPMatch(
                dl_type = ether_types.ETH_TYPE_IP,
                nw_tos = 8,
                nw_dst = '192.168.1'
            )
            
            match_new = datapath.ofproto_parser.OFPMatch(
                dl_type = ether_types.ETH_TYPE_IP,
                nw_proto = inet.IPPROTO_UDP,
                # nw_src = ip_src,
                nw_dst = '200.0.0',
            )
            
            actions_new = [
                datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:03:01"),
                datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:04:01"),
                datapath.ofproto_parser.OFPActionSetNwSrc('200.0.0.1'),
                datapath.ofproto_parser.OFPActionOutput(3)
            ]
            self.add_flow(datapath, match=match, actions=actions)
            self.add_flow(datapath, match=match_new, actions=actions_new)
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype

        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s in_port=%s", hex(dpid).ljust(4), hex(ethertype), src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port
        
        arp_packet = pkt.get_protocol(arp.arp)
        ip_packet = pkt.get_protocol(ipv4.ipv4)
        udp_packet = pkt.get_protocol(udp.udp)
        
        if dpid == 0x1A:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                if arp_packet.opcode == arp.ARP_REQUEST:
                    if arp_packet.dst_ip == '192.168.1.1':
                        actions = [datapath.ofproto_parser.OFPActionOutput(msg.in_port)]
                        self.arp_reply(actions, datapath, "00:00:00:00:01:01", src, arp_packet.dst_ip, arp_packet.src_ip)
                    if arp_packet.dst_ip == '200.0.0.1':
                        actions = [datapath.ofproto_parser.OFPActionOutput(msg.in_port)]
                        self.arp_reply(actions, datapath, "00:00:00:00:04:01", src, arp_packet.dst_ip, arp_packet.src_ip)               
                return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                if ip_packet:
                    dst_ip = ip_packet.dst
                    if dst_ip.startswith('192.168.1') or dst_ip.startswith('192.168.2') or dst_ip.startswith('200.0.0'):
                        if dst_ip.startswith('192.168.1'):
                            self.logger.info("Packet in 1A datapath from left LAN: %s ----> %s", ip_packet.src,dst_ip)
                            self.ip_match(datapath, "00:00:00:00:01:01", ARP_TABLE[dst_ip], dst_ip, 2, msg, pkt)
                            
                        
                        if dst_ip.startswith('192.168.2'):
                            self.logger.info("Packet in 1A datapath from left LAN: %s ----> %s", ip_packet.src,dst_ip)
                            self.ip_match(datapath, "00:00:00:00:03:01", "00:00:00:00:03:02", dst_ip, 1, msg, pkt)
                            
                        
                        if dst_ip.startswith('200.0.0'):
                            self.logger.info("Packet destined in h5 with dstIP: %s and srcIP: %s", dst_ip, ip_packet.src)
                            
                            if udp_packet:
                                self.nat_service(datapath, msg.data, ip_packet,udp_packet)
                            
                            
                    else:
                        ip_datagram = msg.data[14:]
                        # print("Src mac %s, Src ip %s, Dst Mac %s, Dst ip %s",eth.src,ip_packet.src,eth.dst,dst_ip)
                        actions = [datapath.ofproto_parser.OFPActionOutput(2)]
                        self.icmp_dest_unreachable(
                            actions,
                            datapath,
                            '00:00:00:00:01:01',
                            eth.src,
                            '192.168.1.1',
                            ip_packet.src,
                            3,
                            1,
                            ip_datagram
                        )
                    return
                     
                return
            return
        if dpid == 0x1B:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                if arp_packet.opcode == arp.ARP_REQUEST:
                    if arp_packet.dst_ip == '192.168.2.1':
                        actions = [datapath.ofproto_parser.OFPActionOutput(msg.in_port)]
                        self.arp_reply(actions, datapath, "00:00:00:00:02:01", src, arp_packet.dst_ip, arp_packet.src_ip)
                return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                if ip_packet:
                    dst_ip = ip_packet.dst
                    if dst_ip.startswith('192.168.1') or dst_ip.startswith('192.168.2'):
                        if dst_ip.startswith('192.168.2'):
                            self.logger.info("Packet in 1B datapath from right LAN: %s ----> %s", ip_packet.src,dst_ip)
                            self.ip_match(datapath, "00:00:00:00:02:01", ARP_TABLE[dst_ip], dst_ip, 2, msg, pkt)
                            
                        
                        if dst_ip.startswith('192.168.1'):
                            self.logger.info("Packet in 1B datapath from left LAN: %s ----> %s", ip_packet.src,dst_ip)
                            self.ip_match(datapath, "00:00:00:00:03:01", "00:00:00:00:03:02", dst_ip, 1, msg, pkt)
                            
                    else:
                        ip_datagram = msg.data[14:]
                        # print("Src mac %s, Src ip %s, Dst Mac %s, Dst ip %s",eth.src,ip_packet.src,eth.dst,dst_ip)
                        actions = [datapath.ofproto_parser.OFPActionOutput(2)]
                        self.icmp_dest_unreachable(
                            actions,
                            datapath,
                            '00:00:00:00:02:01',
                            eth.src,
                            '192.168.2.1',
                            ip_packet.src,
                            3,
                            1,
                            ip_datagram
                        )
                    return
            return
                 
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        match = datapath.ofproto_parser.OFPMatch(
            in_port=msg.in_port, dl_dst=haddr_to_bin(dst))

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

        
    """
    fill in the code here for the ARP reply functions.
    """
    def arp_reply(self, actions,datapath, src_mac, dst_mac, src_ip, dst_ip):
        self.logger.info("ARP REPLY: %s %s ----> %s %s",src_mac,src_ip,dst_mac,dst_ip)

        ofproto = datapath.ofproto
        # Create the reply
        pck = packet.Packet()
        pck.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP, dst=dst_mac, src=src_mac))
        pck.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip, dst_mac=dst_mac, dst_ip=dst_ip))
        
        pck.serialize()
        out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, 
                buffer_id=ofproto.OFP_NO_BUFFER, 
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions, 
                data=pck.data
        )

        datapath.send_msg(out)
        
    def ip_match(self, datapath, src_mac, dst_mac, dst_ip,out_port,msg,pkt):
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(
            dl_type = ether_types.ETH_TYPE_IP,
            nw_dst = dst_ip,
            nw_dst_mask = 24  
        )
                            
        actions = [
            datapath.ofproto_parser.OFPActionSetDlDst(dst_mac),
            datapath.ofproto_parser.OFPActionSetDlSrc(src_mac),
            datapath.ofproto_parser.OFPActionOutput(out_port)
        ]
        
        self.add_flow(datapath, match, actions)
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, 
            buffer_id=msg.buffer_id, 
            in_port=msg.in_port,
            actions=actions, 
            data=pkt.data)
        datapath.send_msg(out)
        

    def icmp_dest_unreachable(self,actions,datapath, eth_src, eth_dst, ip_src, ip_dst, icmp_type, icmp_code, pck):
        self.logger.info("Creating icmp packet!")
        ofproto = datapath.ofproto
        
        new_packet = packet.Packet()
        new_packet.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_IP, src=eth_src, dst=eth_dst))
        new_packet.add_protocol(ipv4.ipv4(src=ip_src, dst=ip_dst, proto=1))
        new_packet.add_protocol(icmp.icmp(type_=icmp_type, code=icmp_code,data=icmp.dest_unreach(data_len=len(pck),data=pck)))
        
        new_packet.serialize()
        data = new_packet.data
        
        out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, 
                buffer_id=ofproto.OFP_NO_BUFFER, 
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions, 
                data=data
        )
        
        datapath.send_msg(out)
    
    def get_available_port(self):
        self.port_counter += 1
        port = self.ports_pool.pop(self.port_counter)
        return port
    
    def nat_service(self, datapath, data, ip_packet, udp_packet):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
    
        ip_src = ip_packet.src
        ip_dst = ip_packet.dst
        
        udp_src = udp_packet.src_port
        udp_dst = udp_packet.dst_port
        
        
        self.offset += 1
        nat_port = 5200 + self.offset
        
        
        match = parser.OFPMatch(
            dl_type = ether_types.ETH_TYPE_IP,
            nw_proto = inet.IPPROTO_UDP,
            nw_src = ip_src,
            nw_dst = ip_dst,
            tp_src = udp_src,
            tp_dst = udp_dst
        )
            
        actions = [
            parser.OFPActionSetDlSrc("00:00:00:00:04:01"),
            parser.OFPActionSetDlDst("00:00:00:00:04:02"),
            parser.OFPActionSetNwSrc('200.0.0.1'),
            parser.OFPActionSetTpSrc(nat_port),
            parser.OFPActionOutput(3)
        ]
        
        match_back = parser.OFPMatch(
            dl_type = ether_types.ETH_TYPE_IP,
            nw_proto = inet.IPPROTO_UDP,
            nw_src = ip_dst,
            nw_dst = '200.0.0.1',
            tp_src = udp_dst,
            tp_dst = nat_port
        )
        
        actions_back = [
            parser.OFPActionSetDlSrc("00:00:00:00:01:01"),
            parser.OFPActionSetDlDst(ARP_TABLE[ip_src]),
            # parser.OFPActionSetNwSrc('192.168.1.1'),
            parser.OFPActionSetNwDst(ip_src),
            parser.OFPActionSetTpSrc(udp_dst),
            parser.OFPActionSetTpDst(udp_src),
            parser.OFPActionOutput(2)
        ]
            
        self.add_flow(datapath, match=match, actions=actions)
        self.add_flow(datapath, match=match_back, actions=actions_back)
        
        out = parser.OFPPacketOut(
            datapath = datapath,
            buffer_id = ofproto.OFP_NO_BUFFER,
            in_port = ofproto.OFPP_CONTROLLER,
            actions = actions,
            data = data
        )
        datapath.send_msg(out)
    
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
