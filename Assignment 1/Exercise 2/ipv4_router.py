from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet.arp import arp
from ryu.lib.packet.packet import Packet
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Network
from ipaddress import IPv4Address
from typing import Optional


class RouteType(Enum):
    LOCAL = "local"
    REMOTE = "remote"

@dataclass
class Route:
    network: IPv4Network
    type: RouteType
    router_ip: IPv4Address
    next_hop_ip: Optional[IPv4Address]
    outport: int



class L3Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    MAC_ADDR = {1: "52:00:00:00:00:01", 2: "52:00:00:00:00:02"}
    ROUTES = {1: [Route(network=IPv4Network("10.0.1.0/28"), type=RouteType.LOCAL, router_ip=IPv4Address("10.0.1.14"), next_hop_ip=None, outport=2),
                  Route(network=IPv4Network("10.0.2.0/24"), type=RouteType.LOCAL, router_ip=IPv4Address("10.0.2.254"), next_hop_ip=None, outport=3),
                  Route(network=IPv4Network("10.0.3.0/26"), type=RouteType.LOCAL, router_ip=IPv4Address("10.0.3.62"), next_hop_ip=None, outport=4),
                  Route(network=IPv4Network("10.0.4.0/30"), type=RouteType.REMOTE, router_ip=IPv4Address("10.0.2.254"), next_hop_ip=IPv4Address("10.0.2.252"), outport=1)],
              2: [Route(network=IPv4Network("10.0.1.0/28"), type=RouteType.REMOTE, router_ip=IPv4Address("10.0.2.252"), next_hop_ip=IPv4Address("10.0.2.254"), outport=2),
                  Route(network=IPv4Network("10.0.2.0/24"), type=RouteType.REMOTE, router_ip=IPv4Address("10.0.2.252"), next_hop_ip=IPv4Address("10.0.2.254"), outport=2),
                  Route(network=IPv4Network("10.0.3.0/26"), type=RouteType.REMOTE, router_ip=IPv4Address("10.0.2.252"), next_hop_ip=IPv4Address("10.0.2.254"), outport=2),
                  Route(network=IPv4Network("10.0.4.0/30"), type=RouteType.LOCAL, router_ip=IPv4Address("10.0.4.2"), next_hop_ip=None, outport=1)]}

    def __init__(self, *args, **kwargs):
        super(L3Switch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def send_packet(self, datapath, port, pkt, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data

        actions = [parser.OFPActionOutput(port=port)]

        if buffer_id:
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=buffer_id,
                                      in_port=ofproto.OFPP_CONTROLLER,
                                      actions=actions,
                                      data=data)
        else:
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_CONTROLLER,
                                      actions=actions,
                                      data=data)

        datapath.send_msg(out)

    # depending on dpid, returns the mac of the corresponding openflow switch
    def get_ofs_mac_for_ip(self, dpid, ip):
        ip = IPv4Address(ip)

        for route in self.ROUTES.get(dpid, []):
            if route.router_ip == ip:
                return self.MAC_ADDR[dpid]
            
        return None


    def do_arp(self, datapath, packet, frame, inPort):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        arpPacket = packet.get_protocol(arp)
        if arpPacket.opcode == 1:
            # arp request
            arp_dstIp = arpPacket.dst_ip
            self.logger.info('received ARP Request %s => %s (port%d)' %
                             (frame.src, frame.dst, inPort))
            
            ofs_mac = self.get_ofs_mac_for_ip(dpid, arp_dstIp)

            if ofs_mac is not None:
                # an openflow switch was requested
                opcode = 2
                srcMAC = ofs_mac
                srcIP = arp_dstIp
                dstMAC = frame.src
                dstIP = arpPacket.src_ip
                outPort = inPort
                # learn mac 2 port mapping
                self.mac_to_port[dpid][dstMAC] = inPort
                # learn ip 2 mac mapping
                self.ip_to_mac[dpid][dstIP] = dstMAC
                self.logger.info("send ARP reply %s => %s (port%d)" %
                                 (srcMAC, dstMAC, outPort))
            else:
                if arpPacket.dst_ip in self.ip_to_mac[dpid]:
                    # optimization: the switch already knows the mapping and can answer the request
                    opcode = 2
                    srcMAC = self.ip_to_mac[dpid][arpPacket.dst_ip]
                    srcIP = arpPacket.dst_ip
                    dstMAC = frame.src
                    dstIP = arpPacket.src_ip
                    outPort = self.mac_to_port[dpid][dstMAC]
                    self.logger.info("optimization: answer ARP request %s => %s (port%d)" % (
                        srcMAC, dstMAC, outPort))
                else:
                    # forward arp request
                    opcode = 1
                    srcMAC = frame.src
                    srcIP = arpPacket.src_ip
                    dstMAC = frame.dst
                    dstIP = arpPacket.dst_ip
                    outPort = ofproto.OFPP_FLOOD
                    # learn mac 2 port mapping
                    self.mac_to_port[dpid][srcMAC] = inPort
                    # learn ip 2 mac mapping
                    self.ip_to_mac[dpid][srcIP] = srcMAC
                    self.logger.info("forward ARP request %s => %s (port%d)" % (
                        srcMAC, dstMAC, outPort))
        elif arpPacket.opcode == 2:                    
            # arp reply
            srcMAC = frame.src
            srcIP = arpPacket.src_ip
            dstMAC = frame.dst
            dstIP = arpPacket.dst_ip
             # learn ip 2 mac mapping
            self.ip_to_mac[dpid][srcIP] = srcMAC
            # learn mac 2 port mapping
            self.mac_to_port[dpid][srcMAC] = inPort

            # arp reply was directed to gateway no forwarding
            if dstMAC == self.MAC_ADDR[dpid]:
                self.logger.info("learned ARP reply for gateway: %s is at %s on port %d", srcIP, srcMAC, inPort)
                return
            
            if dstMAC not in self.mac_to_port[dpid]:
                return
            
            # forward arp reply
            outPort = self.mac_to_port[dpid][dstMAC]
            opcode = 2
            
            self.logger.info('forward ARP reply %s => %s (port%d)' %
                              (frame.src, frame.dst, inPort))
        self.send_arp(datapath, opcode, srcMAC, srcIP, dstMAC, dstIP, outPort)

    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        if opcode == 1:
            targetMac = "FF:FF:FF:FF:FF:FF"
            targetIp = dstIp
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp
        e = ethernet.ethernet(dstMac, srcMac, ether_types.ETH_TYPE_ARP)
        a = arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)

        self.send_packet(datapath, outPort, p)

    def do_icmp(self, datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp):
        if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST:
            return
        pkt = packet.Packet()
        dst_ip = pkt_ipv4.dst
        dpid = datapath.id

        ofs_mac = self.get_ofs_mac_for_ip(dpid, pkt_ipv4.dst)

        if ofs_mac is None:
            self.logger.info("ICMP request for unknown openflow switch IP %s on switch %s", dst_ip, dpid)
            return 


        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src=ofs_mac))
        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                                   src=dst_ip,
                                   proto=pkt_ipv4.proto))
        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                   code=icmp.ICMP_ECHO_REPLY_CODE,
                                   csum=0,
                                   data=pkt_icmp.data))
        self.logger.info("do icmp: %s" % (pkt,))
        self.send_packet(datapath, port, pkt)

    def do_l2_switch(self, datapath, dpid, packet, frame, in_port, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if frame.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][frame.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=frame.dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if buffer_id == ofproto.OFP_NO_BUFFER:
            data = packet.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


    # Longest Prefix Matching Lookup
    def lookup_route(self, dpid, dst_ip):
        dst_ip = IPv4Address(dst_ip)
        
        best_route = None

        for route in self.ROUTES[dpid]:
            if dst_ip in route.network:
                if best_route == None:
                    best_route = route
                elif route.network.prefixlen > best_route.network.prefixlen:
                    best_route = route
        return best_route
    
    


    def do_l3_routing(self, datapath, pkt):
        pkt_eth = pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        dpid = datapath.id
        parser = datapath.ofproto_parser

        dst_ip = pkt_ipv4.dst
        route = self.lookup_route(dpid, dst_ip)

        if route is None:
            self.logger.info("Unknown destination IP %s", dst_ip)
            return

        out_port = route.outport


        if route.type == RouteType.LOCAL:
            # destination in same subnet, target mac adress is destination mac adress
            arp_target_ip = dst_ip
        else:
            # destination outside of subnet, target mac adress is next hop mac adress
            arp_target_ip = str(route.next_hop_ip)

        ofs_mac = self.MAC_ADDR[dpid]

        if arp_target_ip not in self.ip_to_mac[dpid]:
            # arp request for dst ip must be sent
            # as flooding port use the port at which the host is part of the network
            flooding_port = route.outport
            broadcast_mac = "FF:FF:FF:FF:FF:FF"

            self.logger.info("send ARP request %s => %s (port%d) from gateway %s" % (
                ofs_mac, broadcast_mac, flooding_port, route.router_ip))
            
            self.send_arp(datapath=datapath, opcode=1, srcMac=ofs_mac, srcIp=str(route.router_ip), dstMac=broadcast_mac, dstIp=arp_target_ip, outPort=flooding_port)
            
            # first ping message is discarded
            return 
        
        dst_mac = self.ip_to_mac[dpid].get(arp_target_ip)
        if dst_mac is None:
            return
        
        # add flow 
        actions = [
            parser.OFPActionSetField(eth_src=ofs_mac),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(route.outport)
        ]   

        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst=dst_ip
        )

        self.add_flow(datapath, 10, match, actions)


        # modify header of original packet 
        pkt_eth.src = ofs_mac
        pkt_eth.dst = dst_mac
        self.send_packet(datapath, out_port, pkt)
        

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst_mac = eth.dst
        src_mac = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.ip_to_mac.setdefault(dpid, {})

        # learn mac to port mapping
        if src_mac not in self.mac_to_port[dpid]:
            self.mac_to_port[dpid][src_mac] = in_port

        if eth.ethertype in (ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6):
            # ignore lldp and ipv6 packets
            return
        
        self.logger.info(
            "packet in dpid: %s, src: %s, dest: %s, in_port: %s", dpid, src_mac, dst_mac, in_port)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.do_arp(datapath, pkt, eth, in_port)
            return

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            dst_ip = IPv4Address(ipv4_pkt.dst)

            route = self.lookup_route(dpid, dst_ip)

            if route is None:
                return
            
            # check if packet is for this switch (L3)
            if dst_ip == route.router_ip:
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                if icmp_pkt:
                    self.logger.info("switch %s received icmp packet", dpid)                
                    self.do_icmp(datapath, in_port, eth, ipv4_pkt, icmp_pkt)
                return        
            # route packet into another subnet
            elif dst_mac == self.MAC_ADDR[dpid]:
                self.logger.info("sending packet to subnet: %s", ipv4_pkt.dst)                
                self.do_l3_routing(datapath, pkt)
                return
            else:
                # packet is not for this switch, so do l2 switching
                self.do_l2_switch(datapath, dpid, pkt, eth, in_port, msg.buffer_id)
                return
        return
