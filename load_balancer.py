from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import arp, ethernet, ipv4, icmp

log = core.getLogger()

class VirtualIPLoadBalancer:
    def __init__(self, connection):
        self.connection = connection
        self.servers = [
            {"ip": IPAddr("10.0.0.5"), "mac": EthAddr("00:00:00:00:00:05")},
            {"ip": IPAddr("10.0.0.6"), "mac": EthAddr("00:00:00:00:00:06")},
        ]
        self.client_ports = {}
        self.virtual_mac = EthAddr("00:00:00:00:00:10")
        self.current_server = 0

        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        packet = event.parsed

        if packet.type == packet.ARP_TYPE:
            self._handle_arp(event, packet)
        elif isinstance(packet.next, ipv4):
            ip_packet = packet.next
            if isinstance(ip_packet.next, icmp):
                if ip_packet.srcip in [s["ip"] for s in self.servers]:
                    self._handle_icmp_reply(event, packet)
                else:
                    self._handle_icmp_request(event, packet)

    def _handle_arp(self, event, packet):
        arp_packet = packet.payload
        if arp_packet.protodst not in [s["ip"] for s in self.servers]: #handle all arp request that are not for servers.
            arp_reply = arp()
            arp_reply.hwtype = arp_packet.hwtype
            arp_reply.prototype = arp_packet.prototype
            arp_reply.hwlen = arp_packet.hwlen
            arp_reply.protolen = arp_packet.protolen
            arp_reply.opcode = arp.REPLY
            arp_reply.hwdst = arp_packet.hwsrc
            arp_reply.protodst = arp_packet.protosrc
            arp_reply.hwsrc = self.virtual_mac
            arp_reply.protosrc = arp_packet.protodst #send the virtual address back.

            eth = ethernet()
            eth.src = self.virtual_mac
            eth.dst = packet.src
            eth.type = ethernet.ARP_TYPE
            eth.payload = arp_reply

            msg = of.ofp_packet_out()
            msg.data = eth.pack()
            msg.actions.append(of.ofp_action_output(port=event.port))
            self.connection.send(msg)

            selected_server = self.servers[self.current_server]
            self.current_server = (self.current_server + 1) % len(self.servers)

            client_ip = arp_packet.protosrc
            self.client_ports[client_ip] = event.port

            self._install_flow_rules(event.port, client_ip, selected_server, arp_packet.protodst) #use the destination IP.
            log.info(f"ARP request from {client_ip} mapped to {selected_server['ip']} for virtual IP {arp_packet.protodst}")

        elif arp_packet.protosrc in [s["ip"] for s in self.servers]:
            #handle ARP request from servers.
            client_ip = arp_packet.protodst
            if client_ip in self.client_ports:
                dest_port = self.client_ports[client_ip]
                arp_reply = arp()
                arp_reply.hwtype = arp_packet.hwtype
                arp_reply.prototype = arp_packet.prototype
                arp_reply.hwlen = arp_packet.hwlen
                arp_reply.protolen = arp_packet.protolen
                arp_reply.opcode = arp.REPLY
                arp_reply.hwdst = arp_packet.hwsrc
                arp_reply.protodst = arp_packet.protosrc
                arp_reply.hwsrc = self.virtual_mac
                arp_reply.protosrc = arp_packet.protodst

                eth = ethernet()
                eth.src = self.virtual_mac
                eth.dst = packet.src
                eth.type = ethernet.ARP_TYPE
                eth.payload = arp_reply

                msg = of.ofp_packet_out()
                msg.data = eth.pack()
                msg.actions.append(of.ofp_action_output(port=event.port))
                self.connection.send(msg)

    def _handle_icmp_request(self, event, packet):
        """
        Handles incoming ICMP requests and forwards them to h5 or h6.
        """
        ip_packet = packet.next
        client_ip = ip_packet.srcip
        virtual_ip = ip_packet.dstip

        if client_ip in self.client_ports and virtual_ip not in [s["ip"] for s in self.servers]:
            selected_server = None
            for server in self.servers:
                if server['ip'] == packet.next.dstip:
                    selected_server = server
                    break
            if selected_server is None:
                selected_server = self.servers[self.current_server]
                self.current_server = (self.current_server + 1) % len(self.servers)

            self._install_flow_rules(event.port, client_ip, selected_server, virtual_ip)
            log.info(f"ICMP request from {client_ip} redirected to {selected_server['ip']} for virtual IP {virtual_ip}")
        else:
            log.warning(f"ICMP request from {client_ip} to {ip_packet.dstip} dropped, no client port found.")

    def _handle_icmp_reply(self, event, packet):
        ip_packet = packet.next
        server_ip = ip_packet.srcip
        client_ip = ip_packet.dstip
        if client_ip in self.client_ports:
            msg = of.ofp_flow_mod()
            msg.match.in_port = event.port
            msg.match.dl_type = 0x0800
            msg.match.nw_proto = ipv4.ICMP_PROTOCOL
            msg.match.nw_src = server_ip
            msg.match.nw_dst = client_ip

            msg.actions.append(of.ofp_action_nw_addr.set_src(ip_packet.dstip)) #send the virtual address back.
            msg.actions.append(of.ofp_action_dl_addr.set_src(self.virtual_mac))
            msg.actions.append(of.ofp_action_output(port=self.client_ports[client_ip]))
            self.connection.send(msg)
            log.info(f"ICMP reply from {server_ip} rewritten to {ip_packet.dstip}")

    def _install_flow_rules(self, in_port, client_ip, server, virtual_ip):
        # Client to Server
        msg = of.ofp_flow_mod()
        msg.match.in_port = in_port
        msg.match.dl_type = 0x0800
        msg.match.nw_proto = ipv4.ICMP_PROTOCOL
        msg.match.nw_dst = virtual_ip
        msg.match.nw_src = client_ip

        msg.actions.append(of.ofp_action_nw_addr.set_dst(server["ip"]))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(server["mac"]))
        msg.actions.append(of.ofp_action_output(port=self.connection.ports[server["mac"]]))
        self.connection.send(msg)

        # Server to Client
        msg = of.ofp_flow_mod()
        msg.match.in_port = self.connection.ports[server["mac"]]
        msg.match.dl_type = 0x0800
        msg.match.nw_proto = ipv4.ICMP_PROTOCOL
        msg.match.nw_src = server["ip"]
        msg.match.nw_dst = client_ip

        msg.actions.append(of.ofp_action_nw_addr.set_src(virtual_ip))
        msg.actions.append(of.ofp_action_dl_addr.set_src(self.virtual_mac))
        msg.actions.append(of.ofp_action_output(port=in_port))
        self.connection.send(msg)

def launch():
    def start_switch(event):
        log.info(f"Starting Virtual IP Load Balancer on switch {event.connection}")
        VirtualIPLoadBalancer(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)