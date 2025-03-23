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

# Cache to store client MAC addresses, selected servers and requested IP addresses
client_cache = {}  # Format: {client_ip: {"mac": client_mac, "server": selected_server. "requested_ip": requested_ip}}

class LoadBalancer(object):
    def __init__(self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        self.connection = event.connection

    def _handle_PacketIn(self, event):
        """
        Handle incoming packets from the switch.

        Processes ARP and ICMP packets:
        - For ARP requests:
            - From clients: Responds with the MAC address of a server selected in round-robin fashion.
            - From servers: Responds with the MAC address of the client to enable reverse communication.
        - For ICMP echo requests: Forwards packets to the server assigned to the client.
        - For ICMP echo replies: Rewrites the source IP to the virtual IP before forwarding to the client.
        
        Args:
            event (ofp_event.EventOFPPacketIn): The event object containing the incoming packet and metadata.
        """
        global current_server

        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        # Handle ARP requests
        if packet.type == 0x0806:
            arp_packet = packet.payload
            requested_ip = arp_packet.protodst
            client_ip = arp_packet.protosrc
            client_mac = packet.src


            # Check if the ARP request is from a server for a client's IP
            if requested_ip in client_cache and arp_packet.protosrc in SERVER_IPS:
                log.info(f"ARP request from server {arp_packet.protosrc} for client IP: {requested_ip}")

                # Create ARP reply with the cached client's MAC address
                arp_reply = arp()
                arp_reply.hwsrc = client_cache[requested_ip]["mac"]
                arp_reply.hwdst = arp_packet.hwsrc
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = requested_ip
                arp_reply.protodst = arp_packet.protosrc

                ether = ethernet()
                ether.type = 0x0806
                ether.src = client_cache[requested_ip]["mac"]
                ether.dst = arp_packet.hwsrc
                ether.payload = arp_reply

                # Send ARP reply
                msg = of.ofp_packet_out()
                msg.data = ether.pack()
                msg.actions.append(of.ofp_action_output(port=event.port))
                event.connection.send(msg)
                log.info(f"Sent ARP reply: {requested_ip} is-at {client_cache[requested_ip]['mac']}")

            # Check if the ARP request is for the virtual IP
            else:
                log.info(f"ARP request for virtual IP: {requested_ip} from client: {client_ip}")

                # Select the next server in round-robin fashion
                selected_server = current_server
                current_server = (current_server + 1) % len(SERVER_IPS)

                # Cache the client's MAC address and selected server
                client_cache[client_ip] = {"mac": client_mac, "server": selected_server, "requested_ip": requested_ip}
                log.info(f"Cached client: {client_ip} -> MAC: {client_mac}, Server: {SERVER_IPS[selected_server]}")

                # Create ARP reply with the selected server's MAC address
                arp_reply = arp()
                arp_reply.hwsrc = SERVER_MACS[selected_server]
                arp_reply.hwdst = client_mac
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = requested_ip
                arp_reply.protodst = client_ip

                ether = ethernet()
                ether.type = 0x0806
                ether.src = SERVER_MACS[selected_server]
                ether.dst = client_mac
                ether.payload = arp_reply

                # Send ARP reply
                msg = of.ofp_packet_out()
                msg.data = ether.pack()
                msg.actions.append(of.ofp_action_output(port=event.port))
                event.connection.send(msg)
                log.info(f"Sent ARP reply: {requested_ip} is-at {SERVER_MACS[selected_server]}")

        # Handle ICMP (ping) traffic
        elif packet.type == 0x0800:
            ip_packet = packet.payload
            if ip_packet.protocol == ipv4.ICMP_PROTOCOL:
                icmp_packet = ip_packet.payload
                if isinstance(icmp_packet, icmp):
                    # Check if the packet is an ICMP echo reply
                    if ip_packet.srcip in SERVER_IPS:
                        server_ip = ip_packet.srcip
                        client_ip = ip_packet.dstip

                        # Retrieve the cached client MAC address
                        if client_ip in client_cache:
                            client_mac = client_cache[client_ip]["mac"]
                            log.info(f"Forwarding ICMP echo reply from server {server_ip} to client {client_ip}")

                            msg = of.ofp_packet_out()
                            msg.data = packet.pack()
                            msg.actions.append(of.ofp_action_nw_addr.set_src(client_cache[client_ip]["requested_ip"]))  # Rewrite source IP to virtual IP
                            msg.actions.append(of.ofp_action_output(port=self.get_client_port(client_ip)))
                            event.connection.send(msg)
                            log.info(f"Forwarded ICMP echo reply to client {client_ip}")
                        else:
                            log.warning(f"No cached client MAC found for IP: {client_ip}")
                    
                    # Check if the destination IP is a virtual IP
                    elif ip_packet.dstip not in SERVER_IPS:
                        client_ip = ip_packet.srcip
                        client_mac = packet.src

                        # Retrieve the cached server for this client
                        if client_ip in client_cache:
                            selected_server = client_cache[client_ip]["server"]
                            log.info(f"Using cached server {SERVER_IPS[selected_server]} for client {client_ip}")

                            msg = of.ofp_packet_out()
                            msg.data = packet.pack()
                            msg.actions.append(of.ofp_action_dl_addr.set_dst(SERVER_MACS[selected_server]))
                            msg.actions.append(of.ofp_action_nw_addr.set_dst(SERVER_IPS[selected_server]))
                            msg.actions.append(of.ofp_action_output(port=self.get_server_port(SERVER_IPS[selected_server])))
                            event.connection.send(msg)
                            log.info(f"Forwarded ICMP packet to {SERVER_IPS[selected_server]}")
                        else:
                            log.warning(f"No cached server found for client {client_ip}")

    def get_server_port(self, server_ip):
        """Return the switch port connected to the server."""
        if server_ip == SERVER_IPS[0]:
            log.info(f"Mapping {server_ip} to port 5")
            return 5
        else:
            log.info(f"Mapping {server_ip} to port 6")
            return 6
        
    def get_client_port(self, client_ip):
        """Return the switch port connected to the client."""
        client_ports = {
            IPAddr("10.0.0.1"): 1,
            IPAddr("10.0.0.2"): 2,
            IPAddr("10.0.0.3"): 3,
            IPAddr("10.0.0.4"): 4,
        }
        return client_ports.get(client_ip, None)

def launch():
    core.registerNew(LoadBalancer)