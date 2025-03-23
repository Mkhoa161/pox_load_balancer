from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import ipv4, icmp

log = core.getLogger()

class LoadBalancer:
    def __init__(self, connection):
        self.connection = connection  # Store switch connection
        self.servers = [  # List of backend servers (h5 & h6)
            {"ip": IPAddr("10.0.0.5"), "mac": EthAddr("00:00:00:00:00:05")},
            {"ip": IPAddr("10.0.0.6"), "mac": EthAddr("00:00:00:00:00:06")},
        ]
        self.client_ports = {}  # Store client-port mappings
        self.current_server = 0  # Round-robin counter

        connection.addListeners(self)  # Listen for OpenFlow events

    def _handle_PacketIn(self, event):
        """
        Handles incoming packets and processes ICMP (ping) requests.
        """
        packet = event.parsed  # Parse the packet
        
        if isinstance(packet.next, ipv4):  # Check if it's an IPv4 packet
            ip_packet = packet.next
            if isinstance(ip_packet.next, icmp):  # If it's an ICMP packet
                if ip_packet.srcip in [s["ip"] for s in self.servers]:  
                    self.handle_reply(event, packet)  # If from h5/h6, handle reply
                else:
                    self.handle_request(event, packet)  # Otherwise, balance the request

    def handle_request(self, event, packet):
        """
        Handles incoming ICMP requests and forwards them to h5 or h6.
        """
        ip_packet = packet.next
        client_ip = ip_packet.srcip  # Get client IP
        selected_server = self.servers[self.current_server]  # Choose server (h5/h6)
        self.current_server = (self.current_server + 1) % len(self.servers)  # Round-robin

        self.client_ports[client_ip] = event.port  # Store client port

        # Install OpenFlow rule to forward ICMP request to h5/h6
        msg = of.ofp_flow_mod()
        msg.match.in_port = event.port  # Match client port
        msg.match.dl_type = 0x0800  # Match IPv4 packets
        msg.match.nw_proto = ipv4.ICMP_PROTOCOL  # Match ICMP (ping)
        msg.match.nw_src = client_ip  # Match source IP
        msg.match.nw_dst = ip_packet.dstip  # Original destination IP

        # Rewrite destination IP & MAC to selected server
        msg.actions.append(of.ofp_action_nw_addr.set_dst(selected_server["ip"]))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(selected_server["mac"]))

        # Forward packet to server
        msg.actions.append(of.ofp_action_output(port=event.port))  
        self.connection.send(msg)

        log.info("Ping from %s redirected to %s", client_ip, selected_server["ip"])

    def handle_reply(self, event, packet):
        """
        Handles ICMP replies from h5/h6 and rewrites them back to the original destination.
        """
        ip_packet = packet.next
        server_ip = ip_packet.srcip  # Get real server IP
        client_ip = ip_packet.dstip  # Get original client IP

        # Install OpenFlow rule to rewrite the reply source
        msg = of.ofp_flow_mod()
        msg.match.in_port = event.port  # Match server port
        msg.match.dl_type = 0x0800  # Match IPv4
        msg.match.nw_proto = ipv4.ICMP_PROTOCOL  # Match ICMP
        msg.match.nw_src = server_ip  # Match real server IP
        msg.match.nw_dst = client_ip  # Match client IP

        # Rewrite source IP & MAC to original destination
        msg.actions.append(of.ofp_action_nw_addr.set_src(ip_packet.dstip))
        msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr("00:00:00:00:00:10")))  # Fake MAC for VIP

        # Forward packet to client
        msg.actions.append(of.ofp_action_output(port=self.client_ports[client_ip]))  
        self.connection.send(msg)

        log.info("Ping reply from %s rewritten to original IP %s", server_ip, ip_packet.dstip)

def launch():
    """
    Starts the POX controller application.
    """
    def start_switch(event):
        log.info("Starting Ping Load Balancer on switch %s", event.connection)
        LoadBalancer(event.connection)  # Attach the load balancer to the switch

    core.openflow.addListenerByName("ConnectionUp", start_switch)  # Listen for switch connection
