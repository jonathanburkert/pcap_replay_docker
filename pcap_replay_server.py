from protoShark.write import WireWriter
from protoShark.dissect import Server
from protoShark.dissect import Client
import binascii
import time
from netaddr import IPAddress, IPNetwork
import json
import re
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
import subprocess
import sys
import argparse


class RequestHandler(BaseHTTPRequestHandler):

    def do_POST(self):

        if re.search('/execute.*', self.path) != None:

            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            post_data = json.loads(post_data)
            ip_map = post_data.get('ip_map')
            pcap_name = post_data.get('pcap_name')
            
            run_scenario(ip_map, pcap_name)

            # Causes Cerebro to error :-(
            message = "\n{pcap_name} replay complete.\n".format(pcap_name=pcap_name)
            self.wfile.write(message)

        elif re.search('/update.*', self.path) != None:

            # Return an update of available scenarios to Cerebro
            self.wfile.write("Under Construction!!!")


def run_scenario(ip_map, pcap_name):

        pcap_path = args.pcap_path
        replay_interface = [args.replay_interface]
        named_pipe = args.named_pipe
        options = '-r {pcap}'.format(pcap=pcap_path+pcap_name)
        Server.create_as_process(named_pipe, options)

        # Magic?!?!
        time.sleep(1)

        client = Client(named_pipe)
        client.connect()

        ww = WireWriter()
        ww.open_interfaces_for_sending(replay_interface)

        # Converting ip_map to IPNetwork objects
        ip_map = {IPNetwork(k): IPNetwork(v) for k,v in ip_map.iteritems()}
        # Creating a list of IPNetwork's we are interested in modifying
        unmod_nets = ip_map.keys()

        while True:
            pkt = client.read_next()
            if pkt is None:
                break

            try:
                attrs = pkt.get_attributes()
                delta = float(attrs['frame.time_delta'][0].get_fvalue())
                ipv4 = attrs.get('ip') and attrs.get('ip.version')[0].get_fvalue() == '4'
            except:
                ipv4 = False

            if ip_map and ipv4:

                src_ip = attrs['ip.src'][0].get_fvalue()
                dest_ip = attrs['ip.dst'][0].get_fvalue()

                # Need to find an efficient way to avoid this
                src_ip = mod_network(src_ip, unmod_nets, ip_map)
                src_ip = dd_2_hex(src_ip)
                pkt.set_attribute(src_ip, "ip.src")

                dest_ip = mod_network(dest_ip, unmod_nets, ip_map)
                dest_ip = dd_2_hex(dest_ip)
                pkt.set_attribute(dest_ip, 'ip.dst')

            # Maintaining original PCAP timing, doesn't work :-(
            if delta > 1:
                time.sleep(delta)

            pkt_data = binascii.a2b_hex(pkt.get_pkt_data())
            ww.write(pkt_data)

        ww.close_sending_interfaces()

        subprocess.Popen('rm -rf {}'.format(named_pipe).split())


def dd_2_hex(ip_addr):

    return ''.join([hex(int(x))[2:].rjust(2, "0") for x in ip_addr.split(".")])


def mod_network(ip_addr, unmod_nets, ip_map):

    ip_addr = IPAddress(ip_addr)

    for net in unmod_nets:
        in_network = ip_addr in net
        if in_network:
            break

    if not in_network:
        return ip_addr.format()

    # Mapping current IP to mod IP
    net = ip_map[net]

    # Converting IPs to binary, only keeping the host and network bits respectively
    ip_addr = ip_addr.bits().replace('.', '')[net.prefixlen:]
    net = net.network.bits().replace('.', '')[:net.prefixlen]

    # Modified IP address
    ip_addr = net + ip_addr
    octet = 8
    ip_addr = '.'.join([str(int(ip_addr[i:i + octet], 2)) for i in range(0, len(ip_addr), octet)])

    return ip_addr


parser = argparse.ArgumentParser()
parser.add_argument("--ip", action="store", dest="server_ip", default="127.0.0.1", type=str)
parser.add_argument("--port", action="store", dest="server_port", default=7000, type=int)
parser.add_argument("--pcap-path", action="store", dest="pcap_path", default="/pcap_replay/pcap/", type=str)
parser.add_argument("--interface", action="store", dest="replay_interface",required=True , type=str)
parser.add_argument("--named-pipe", action="store", dest="named_pipe", default="/tmp/named_pipe", type=str)

args = parser.parse_args()

server = HTTPServer((args.server_ip, args.server_port), RequestHandler)
server.serve_forever()
