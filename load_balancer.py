from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp

log = core.getLogger()

# Real server IPs and MACs
SERVER_IPS = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]
SERVER_MACS = [EthAddr("00:00:00:00:00:05"), EthAddr("00:00:00:00:00:06")]

# Round-robin counter
current_server = 0

class LoadBalancer(object):
    def __init__(self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        self.connection = event.connection

    def _handle_PacketIn(self, event):
        global current_server

        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        # Handle ARP requests
        if packet.type == 0x0806:
            arp_packet = packet.payload
            requested_ip = arp_packet.protodst

            # Check if the requested IP is not a real server IP
            if requested_ip not in SERVER_IPS:
                # Select the next server in round-robin fashion
                selected_server = current_server
                current_server = (current_server + 1) % len(SERVER_IPS)

                # Create ARP reply
                arp_reply = arp()
                arp_reply.hwsrc = SERVER_MACS[selected_server]
                arp_reply.hwdst = arp_packet.hwsrc
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = requested_ip  # Use the requested virtual IP
                arp_reply.protodst = arp_packet.protosrc

                ether = ethernet()
                ether.type = 0x0806
                ether.src = SERVER_MACS[selected_server]
                ether.dst = arp_packet.hwsrc
                ether.payload = arp_reply

                # Send ARP reply
                msg = of.ofp_packet_out()
                msg.data = ether.pack()
                msg.actions.append(of.ofp_action_output(port=event.port))
                event.connection.send(msg)

                # Install OpenFlow rules for the selected server
                self.install_rules(event, requested_ip, SERVER_IPS[selected_server], SERVER_MACS[selected_server])

        # Handle ICMP (ping) traffic
        elif packet.type == 0x0800:
            ip_packet = packet.payload
            if ip_packet.protocol == ipv4.ICMP_PROTOCOL:
                icmp_packet = ip_packet.payload
                if isinstance(icmp_packet, icmp):
                    # Check if the destination IP is a virtual IP
                    if ip_packet.dstip not in SERVER_IPS:
                        # Forward the packet to the selected server
                        selected_server = current_server
                        current_server = (current_server + 1) % len(SERVER_IPS)

                        # Rewrite the destination IP to the selected server's IP
                        msg = of.ofp_packet_out()
                        msg.data = packet.pack()
                        msg.actions.append(of.ofp_action_dl_addr.set_dst(SERVER_MACS[selected_server]))
                        msg.actions.append(of.ofp_action_nw_addr.set_dst(SERVER_IPS[selected_server]))
                        msg.actions.append(of.ofp_action_output(port=self.get_server_port(SERVER_IPS[selected_server])))
                        event.connection.send(msg)

    def install_rules(self, event, virtual_ip, server_ip, server_mac):
        # Rule for traffic from client to server
        msg = of.ofp_flow_mod()
        msg.match.in_port = event.port
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_dst = virtual_ip  # Match the virtual IP
        msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        msg.actions.append(of.ofp_action_output(port=self.get_server_port(server_ip)))
        event.connection.send(msg)

        # Rule for traffic from server to client
        msg = of.ofp_flow_mod()
        msg.match.in_port = self.get_server_port(server_ip)
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_src = server_ip
        msg.match.nw_dst = virtual_ip
        msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr("00:00:00:00:00:00")))  # Virtual MAC
        msg.actions.append(of.ofp_action_nw_addr.set_src(virtual_ip))  # Rewrite source IP to virtual IP
        msg.actions.append(of.ofp_action_output(port=event.port))
        event.connection.send(msg)

    def get_server_port(self, server_ip):
        # This function should return the switch port connected to the server
        if server_ip == SERVER_IPS[0]:
            return 5  
        else:
            return 6 

def launch():
    core.registerNew(LoadBalancer)