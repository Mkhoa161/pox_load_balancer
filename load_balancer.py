from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet

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
        if packet.type == packet.ARP_TYPE:
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
                ether.type = ethernet.ARP_TYPE
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
        msg.match.nw_dst = packet.next.protosrc
        msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr("00:00:00:00:00:00")))  # Virtual MAC
        msg.actions.append(of.ofp_action_nw_addr.set_src(virtual_ip))  # Rewrite source IP to virtual IP
        msg.actions.append(of.ofp_action_output(port=event.port))
        event.connection.send(msg)

    def get_server_port(self, server_ip):
        # This function should return the switch port connected to the server
        # You can hardcode this or dynamically discover it
        if server_ip == SERVER_IPS[0]:
            return 5  # Assuming h5 is connected to port 5
        else:
            return 6  # Assuming h6 is connected to port 6

def launch():
    core.registerNew(LoadBalancer)