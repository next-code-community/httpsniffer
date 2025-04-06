#!/usr/bin/env python3
from os import geteuid, path, makedirs
from pickle import load, dump
from scapy.all import sniff, IP, Raw, TCP, UDP
from scapy.layers.http import HTTPRequest
from datetime import date, datetime
from optparse import OptionParser
from colorama import Fore, Back, Style
from time import strftime, localtime
import sys
import re
import json
import csv

packets_global, verbose, filter_ip, filter_port, packets_limit = [], True, None, None, 0
save_format, log_file, stats_interval, dns_resolve, hide_raw, output_format = "pickle", None, 0, False, False, "text"

status_color = {
    '+': Fore.GREEN,
    '-': Fore.RED,
    '*': Fore.YELLOW,
    ':': Fore.CYAN,
    ' ': Fore.WHITE,
    '!': Fore.MAGENTA,
    '?': Fore.BLUE,
}

def get_time():
    return strftime("%H:%M:%S", localtime())

def display(status, data):
    message = f"{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {get_time()}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}"
    print(message)
    if log_file:
        with open(log_file, 'a') as f:
            # Strip ANSI color codes for log file
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            clean_message = ansi_escape.sub('', message)
            f.write(clean_message + '\n')

def get_arguments():
    parser = OptionParser()
    parser.add_option("-i", "--iface", dest="iface", help="Interface on which sniffing has to be done")
    parser.add_option("-v", "--verbose", dest="verbose", help="Display packet details (True/False, Default=True)")
    parser.add_option("-w", "--write", dest="write", help="Dump the packets to a file")
    parser.add_option("-r", "--read", dest="read", help="Read packets from a dump file")
    parser.add_option("-f", "--filter-ip", dest="filter_ip", help="Filter packets by IP address")
    parser.add_option("-p", "--filter-port", dest="filter_port", help="Filter packets by port number")
    parser.add_option("-l", "--limit", dest="limit", help="Limit the number of packets to capture", type="int")
    parser.add_option("-o", "--output", dest="output", help="Output format (text, json, csv)")
    parser.add_option("-s", "--stats", dest="stats", help="Show statistics every N seconds", type="int")
    parser.add_option("-d", "--dns", dest="dns", help="Resolve IP addresses to hostnames", action="store_true")
    parser.add_option("-n", "--no-raw", dest="no_raw", help="Hide raw packet data", action="store_true")
    parser.add_option("-g", "--log", dest="log", help="Log output to a file")
    parser.add_option("-F", "--format", dest="format", help="Save format (pickle, json)")
    parser.add_option("-c", "--count", dest="count", help="Just count packets, don't store", action="store_true")
    parser.add_option("-m", "--mode", dest="mode", help="Capture mode (http, all, tcp, udp)")

    return parser.parse_args()[0]

def check_root():
    return geteuid() == 0

def create_output_dir(filename):
    dir_name = path.dirname(filename)
    if dir_name and not path.exists(dir_name):
        makedirs(dir_name)

def should_process_packet(packet):
    # Apply filters if set
    if filter_ip and IP in packet:
        if packet[IP].src != filter_ip and packet[IP].dst != filter_ip:
            return False

    if filter_port:
        if TCP in packet and packet[TCP].dport != int(filter_port) and packet[TCP].sport != int(filter_port):
            return False
        if UDP in packet and packet[UDP].dport != int(filter_port) and packet[UDP].sport != int(filter_port):
            return False

    # Check capture mode
    if data.mode:
        if data.mode.lower() == "http" and not packet.haslayer(HTTPRequest):
            return False
        elif data.mode.lower() == "tcp" and not TCP in packet:
            return False
        elif data.mode.lower() == "udp" and not UDP in packet:
            return False
    
    return True

def sniff_packets(iface=None):
    try:
        if iface:
            sniff(prn=process_packet, iface=iface, store=False)
        else:
            sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\nSniffing interrupted by user")

def process_packet(packet):
    if not should_process_packet(packet):
        return

    # Check if we hit the packet limit
    if packets_limit and len(packets_global) >= packets_limit:
        display('!', f"Reached packet limit ({packets_limit}). Stopping capture.")
        sys.exit(0)

    if not data.count:
        packets_global.append(packet)

    if not verbose:
        print(f"\rPackets Sniffed = {len(packets_global)}", end='')
    
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        ip = packet[IP].src
        method = packet[HTTPRequest].Method.decode()
        
        if dns_resolve:
            try:
                from socket import gethostbyaddr
                hostname = gethostbyaddr(ip)[0]
                ip_display = f"{ip} ({hostname})"
            except:
                ip_display = ip
        else:
            ip_display = ip

        if verbose:
            if output_format == "json":
                json_data = {"time": get_time(), "ip": ip, "method": method, "url": url}
                display('+', json.dumps(json_data))
            elif output_format == "csv":
                display('+', f"{get_time()},{ip},{method},{url}")
            else:
                display('+', f"{ip_display} : {Back.MAGENTA}{method}{Back.RESET} => {url}")
            
            if packet.haslayer(Raw) and verbose and not hide_raw:
                raw_data = packet[Raw].load
                display('*', f"RAW Data : {raw_data}")

def show_statistics():
    total = len(packets_global)
    http_count = sum(1 for p in packets_global if p.haslayer(HTTPRequest))
    tcp_count = sum(1 for p in packets_global if TCP in p)
    udp_count = sum(1 for p in packets_global if UDP in p)
    
    display(':', f"Statistics:")
    display(' ', f"- Total packets: {total}")
    display(' ', f"- HTTP packets: {http_count} ({http_count/total*100:.1f}% if total > 0 else 0}%)")
    display(' ', f"- TCP packets: {tcp_count} ({tcp_count/total*100:.1f}% if total > 0 else 0}%)")
    display(' ', f"- UDP packets: {udp_count} ({udp_count/total*100:.1f}% if total > 0 else 0}%)")

if __name__ == "__main__":
    data = get_arguments()
    
    # Configure global options
    verbose = False if data.verbose and data.verbose.lower() == "false" else True
    filter_ip = data.filter_ip
    filter_port = data.filter_port
    packets_limit = data.limit if data.limit else 0
    output_format = data.output.lower() if data.output else "text"
    stats_interval = data.stats if data.stats else 0
    dns_resolve = data.dns
    hide_raw = data.no_raw
    log_file = data.log
    save_format = data.format.lower() if data.format else "pickle"

    if log_file:
        create_output_dir(log_file)
        # Clear log file
        open(log_file, 'w').close()
    
    if data.read:
        try:
            with open(data.read, 'rb') as file:
                packets = load(file)
            display('+', f"Reading packets from {Back.MAGENTA}{data.read}{Back.RESET}")
        except FileNotFoundError:
            display('-', f"{Back.MAGENTA}{data.read}{Back.RESET} File not found!")
            exit(1)
        except Exception as e:
            display('-', f"Error reading file {Back.MAGENTA}{data.read}{Back.RESET}: {e}")
            exit(1)
        for packet in packets:
            process_packet(packet)
        show_statistics()
        exit(0)
    
    if not check_root():
        display('-', f"This program requires {Back.MAGENTA}root{Back.RESET} privileges")
        exit(1)
    
    try:
        if data.iface:
            display('+', f"Starting to sniff on interface {Back.MAGENTA}{data.iface}{Back.RESET}")
            if filter_ip:
                display('+', f"Filtering by IP: {Back.MAGENTA}{filter_ip}{Back.RESET}")
            if filter_port:
                display('+', f"Filtering by port: {Back.MAGENTA}{filter_port}{Back.RESET}")
            if packets_limit:
                display('+', f"Limiting capture to {Back.MAGENTA}{packets_limit}{Back.RESET} packets")
            if data.mode:
                display('+', f"Capture mode: {Back.MAGENTA}{data.mode}{Back.RESET}")
            sniff_packets(data.iface)
        else:
            display('+', f"Starting to sniff on default interface")
            sniff_packets()
    except KeyboardInterrupt:
        print()
        display(':', f"Sniffing stopped by user")
    except Exception as e:
        display('-', f"Error during sniffing: {e}")
    
    print()
    display(':', f"Total Packets Sniffed = {Back.MAGENTA}{len(packets_global)}{Back.RESET}")
    show_statistics()
    
    if data.write and not data.count:
        try:
            create_output_dir(data.write)
            if save_format == "json":
                # Can't directly serialize packets to JSON, so save basic info
                simple_packets = []
                for p in packets_global:
                    if p.haslayer(HTTPRequest):
                        packet_info = {
                            "time": get_time(),
                            "src_ip": p[IP].src,
                            "dst_ip": p[IP].dst,
                            "method": p[HTTPRequest].Method.decode(),
                            "host": p[HTTPRequest].Host.decode(),
                            "path": p[HTTPRequest].Path.decode(),
                            "has_raw": p.haslayer(Raw)
                        }
                        simple_packets.append(packet_info)
                with open(data.write, 'w') as file:
                    json.dump(simple_packets, file, indent=2)
            else:  # pickle format
                with open(data.write, 'wb') as file:
                    dump(packets_global, file)
            display('+', f"Packets successfully saved to {Back.MAGENTA}{data.write}{Back.RESET}")
        except Exception as e:
            display('-', f"Error writing to file {Back.MAGENTA}{data.write}{Back.RESET}: {e}")
