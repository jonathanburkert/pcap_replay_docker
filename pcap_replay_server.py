from protoShark.write import FileWriter
from protoShark.dissect import Server
from protoShark.dissect import Client
from protoShark.packets.utils import *
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
            replay_interface = args.replay_interface
            tmp_file = args.tmp_file
            pcap_path = args.pcap_path
            named_pipe = args.named_pipe
            
            modify_pcap(ip_map, pcap_name, named_pipe, pcap_path, tmp_file, replay_interface)
            replay_pcap(tmp_file, replay_interface)

            # Causes Cerebro to error :-(
            #message = "\n{pcap_name} replay complete.\n".format(pcap_name=pcap_name)
            #self.wfile.write(message)

        elif re.search('/capture.*', self.path) != None:

            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            post_data = json.loads(post_data)
            pcap_name = post_data.get('pcap_name')
            vic_ips = post_data.get('vic_ips')
            mal_ips = post_data.get('mal_ips')
            pcap_path = args.pcap_path
            capture_interface = args.capture_interface

            capture_pcap(pcap_name, pcap_path, mal_ips, vic_ips, capture_interface)

            # Return an update of available scenarios to Cerebro
            self.wfile.write("Under Construction!!!")


def modify_pcap(ip_map, pcap_name, named_pipe, pcap_path, tmp_file, replay_interface):


        # Creating the server process and writing packets to named_pipe
        options = '-r {pcap}'.format(pcap=pcap_path+pcap_name)
        Server.create_as_process(named_pipe, options)

        # Magic?!?!
        time.sleep(1)

        # Creating the client to connect to named_pipe and read packets
        client = Client(named_pipe)
        client.connect()

        # Converting ip_map to IPNetwork objects
        ip_map = {IPNetwork(k): IPNetwork(v) for k,v in ip_map.iteritems()}
        # Creating a list of IPNetwork's we are interested in modifying
        unmod_nets = ip_map.keys()

        # Creating file writer object
        fw = FileWriter()
        errbuff = fw.make_pcap_error_buffer()
        pcap = fw.open(tmp_file, errbuff)
        replay_mac = get_replay_mac(replay_interface)

        while True:
            pkt = client.read_next()
            if pkt is None:
                break

            # Setting the src MAC to the replay interface's src MAC, this is neccessary
            # to have the traffic visible to the sensor in Simspace
            pkt.set_attribute(replay_mac, 'eth.src', mustExist=True)

            if ip_map and is_ipv4(pkt):

                attrs = pkt.get_attributes()
                src_ip = attrs['ip.src'][0].get_fvalue()
                dest_ip = attrs['ip.dst'][0].get_fvalue()

                # Checking to see if packet needs modification, difficult because we have
                # a list of CIDR networks we need to see if an IP address falls within
                src_ip = mod_network(src_ip, unmod_nets, ip_map)
                src_ip = dd_2_hex(src_ip)
                pkt.set_attribute(src_ip, "ip.src")

                dest_ip = mod_network(dest_ip, unmod_nets, ip_map)
                dest_ip = dd_2_hex(dest_ip)
                pkt.set_attribute(dest_ip, 'ip.dst')

            utime, ltime = pkt.get_time()
            dataLen = pkt.get_num_bytes()
            pkt_data = binascii.a2b_hex(pkt.get_pkt_data())

            fw.write(pcap, utime, ltime, dataLen, pkt_data, errbuff)

        # Removing named_pipe after we've finished reading, seems to avoid some errors
        # with frequent requests
        subprocess.Popen('rm -rf {}'.format(named_pipe).split())
        fw.close(pcap)


def replay_pcap(tmp_file, replay_interface):

    cmd = "tcpreplay -i {interface} {pcap}".format(interface=replay_interface, pcap=tmp_file)

    proc = subprocess.Popen(cmd.split())
    proc.wait()


def capture_pcap(pcap_name, pcap_path, mal_ips, vic_ips, capture_interface):

    mal_ips = [ip+'/32' if '/' not in ip else ip for ip in mal_ips]
    vic_ips = [ip+'/32' if '/' not in ip else ip for ip in vic_ips]
    cmd = "tcpdump -nnn -i {interface} -w {pcap} ".format(interface=capture_interface, pcap=pcap_path + pcap_name)
    #cmd += "'(" + ' or '.join(["net " + ip for ip in mal_ips]) + ")'"
    #cmd += ' and '
    #cmd += "'(" + ' or '.join(["net " + ip for ip in vic_ips]) + ")'"

    #with open('log', 'a') as f:
    #    f.write(cmd + '\n')

    proc = subprocess.Popen(cmd.split())
    proc.wait()


def get_replay_mac(replay_interface):

    with open('/sys/class/net/'+replay_interface+'/address') as replay_mac:
        replay_mac = replay_mac.readline()[0:17].replace(':','')

    return replay_mac


def dd_2_hex(ip_addr):

    return ''.join([hex(int(x))[2:].rjust(2, "0") for x in ip_addr.split(".")])


def mod_network(ip_addr, unmod_nets, ip_map):

    ip_addr = IPAddress(ip_addr)

    # Looping through the list of unmod_nets and checking if IP is in network, if True then break
    for net in unmod_nets:
        in_network = ip_addr in net
        if in_network:
            break

    # in_network would be False here if IP address wasn't in any of the unmod_networks
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
parser.add_argument("--replay-interface", action="store", dest="replay_interface",required=True , type=str)
parser.add_argument("--capture-interface", action="store", dest="capture_interface",required=True , type=str)
parser.add_argument("--named-pipe", action="store", dest="named_pipe", default="/tmp/named_pipe", type=str)
parser.add_argument("--tmp-file", action="store", dest="tmp_file", default="/tmp/tmp.pcap", type=str)

args = parser.parse_args()

server = HTTPServer((args.server_ip, args.server_port), RequestHandler)
server.serve_forever()
