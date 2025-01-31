#!/usr/bin/env python3

from os import geteuid
from pickle import load, dump
from scapy.all import sniff, IP, Raw
from scapy.layers.http import HTTPRequest
from datetime import date
from optparse import OptionParser
from colorama import Fore, Back, Style
from time import strftime, localtime

packets_global, verbose = [], True

status_color = {
    '+': Fore.GREEN,
    '-': Fore.RED,
    '*': Fore.YELLOW,
    ':': Fore.CYAN,
    ' ': Fore.WHITE,
}

def get_time():
    return strftime("%H:%M:%S", localtime())

def display(status, data):
    print(f"{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {get_time()}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}")

def get_arguments():
    parser = OptionParser()
    parser.add_option("-i", "--iface", dest="iface", help="Interface on which sniffing has to be done")
    parser.add_option("-v", "--verbose", dest="verbose", help="Display packet details (True/False, Default=True)")
    parser.add_option("-w", "--write", dest="write", help="Dump the packets to a file")
    parser.add_option("-r", "--read", dest="read", help="Read packets from a dump file")
    
    return parser.parse_args()[0]  # Restituisce solo le opzioni

def check_root():
    return geteuid() == 0

def sniff_packets(iface=None):
    sniff(prn=process_packet, iface=iface, store=False) if iface else sniff(prn=process_packet, store=False)

def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        packets_global.append(packet)
        if not verbose:
            print(f"\rPackets Sniffed = {len(packets_global)}", end='')

        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        ip = packet[IP].src
        method = packet[HTTPRequest].Method.decode()

        if verbose:
            display('+', f"{ip} : {Back.MAGENTA}{method}{Back.RESET} => {url}")

        if packet.haslayer(Raw) and verbose:
            display('*', f"RAW Data : {packet[Raw].load}")

if __name__ == "__main__":
    data = get_arguments()

    if data.read:
        try:
            with open(data.read, 'rb') as file:
                packets = load(file)
        except FileNotFoundError:
            display('-', f"{Back.MAGENTA}{data.read}{Back.RESET} File not found!")
            exit(1)
        except Exception as e:
            display('-', f"Error reading file {Back.MAGENTA}{data.read}{Back.RESET}: {e}")
            exit(1)

        for packet in packets:
            process_packet(packet)
        exit(0)

    verbose = False if data.verbose and data.verbose.lower() == "false" else True

    if not check_root():
        display('-', f"This program requires {Back.MAGENTA}root{Back.RESET} privileges")
        exit(1)

    if data.iface:
        sniff_packets(data.iface)

    print()
    display(':', f"Total Packets Sniffed = {Back.MAGENTA}{len(packets_global)}{Back.RESET}")

    if data.write:
        try:
            with open(data.write, 'wb') as file:
                dump(packets_global, file)
            display('+', f"Packets successfully saved to {Back.MAGENTA}{data.write}{Back.RESET}")
        except Exception as e:
            display('-', f"Error writing to file {Back.MAGENTA}{data.write}{Back.RESET}: {e}")
