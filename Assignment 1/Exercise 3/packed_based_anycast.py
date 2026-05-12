from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet.arp import arp
from ryu.lib.packet.packet import Packet
from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import List, Optional

@dataclass
class Server:
    ip: IPv4Address
    mac: Optional[str]
    outport: int

@dataclass
class AnycastGroup:
    anycast_ip: IPv4Address
    anycast_mac: str
    servers: List[Server]
    current: int = 0

    def next_server(self) -> Optional[Server]:
        for _ in range(len(self.servers)):
            server = self.servers[self.current]
            self.current = (self.current + 1) % len(self.servers)

            if server.mac is not None:
                return server

        return None


class L3Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    ANYCAST_GROUP = AnycastGroup(
        anycast_ip=IPv4Address("10.0.0.100"),
        anycast_mac="52:00:00:00:00:ff",
        servers=[
            Server(ip=IPv4Address("10.0.0.2"), mac=None, outport=2),
            Server(ip=IPv4Address("10.0.0.3"), mac=None, outport=3),
            Server(ip=IPv4Address("10.0.0.4"), mac=None, outport=4)
        ]
    ) 



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
        
        # on startup get the MAC addresses of all servers in the anycast group
        for server in self.ANYCAST_GROUP.servers:
            self.send_arp(
                datapath=datapath,
                opcode=1,
                srcMac=self.ANYCAST_GROUP.anycast_mac,
                srcIp=str(self.ANYCAST_GROUP.anycast_ip),
                dstMac="FF:FF:FF:FF:FF:FF",
                dstIp=str(server.ip),
                outPort=server.outport
            )

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

    def do_arp(self, datapath, packet, frame, inPort):
        dpid = datapath.id
        ofproto = datapath.ofproto
        arpPacket = packet.get_protocol(arp)

        if arpPacket.opcode == 1:
            # arp request
            arp_dstIp = arpPacket.dst_ip
            self.logger.info('received ARP Request %s => %s (port%d)' %
                            (frame.src, frame.dst, inPort))
                    
            if arp_dstIp == str(self.ANYCAST_GROUP.anycast_ip):
                # anycast service was requested
                opcode = 2
                srcMAC = self.ANYCAST_GROUP.anycast_mac
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

            for server in self.ANYCAST_GROUP.servers:
                if server.ip == IPv4Address(srcIP):
                    server.mac = srcMAC
                    server.outport = inPort
                    self.logger.info(
                        "learned anycast server %s has MAC %s on port %d",
                        server.ip, server.mac, server.outport
                    )
                    break

            # arp reply was directed to gateway no forwarding
            if dstMAC == self.ANYCAST_GROUP.anycast_mac:
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

    
    def do_anycast(self, datapath, in_port, msg):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        server = self.ANYCAST_GROUP.next_server()

        if server is None:
            self.logger.info("no anycast server MAC known yet, sending ARP requests")

            for s in self.ANYCAST_GROUP.servers:
                self.send_arp(
                    datapath=datapath,
                    opcode=1,
                    srcMac=self.ANYCAST_GROUP.anycast_mac,
                    srcIp=str(self.ANYCAST_GROUP.anycast_ip),
                    dstMac="ff:ff:ff:ff:ff:ff",
                    dstIp=str(s.ip),
                    outPort=s.outport
                )

            return

        self.logger.info(
        "anycast: forwarding packet to server %s via port %d",
        server.ip, server.outport
    )

        actions = [parser.OFPActionSetField(eth_dst=server.mac),
                    parser.OFPActionOutput(server.outport)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)





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

    

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                            ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
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

            # check if packet if the packet is for the anycast group
            if dst_ip == self.ANYCAST_GROUP.anycast_ip and dst_mac == self.ANYCAST_GROUP.anycast_mac:
                self.do_anycast(datapath, in_port, msg)
            else:
                self.do_l2_switch(datapath, dpid, pkt, eth, in_port, msg.buffer_id)
        return
