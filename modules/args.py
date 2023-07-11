from modules.network import get_interfaces
from modules.print import print_color

import argparse
import ipaddress
import logging

class Validation:
    '''
    Class for args validation
    '''
    @staticmethod
    def validate_ip_address(ip_address):
        try:
            ipaddress.ip_address(ip_address) # try to convert str to ip address
            return ip_address
        except ValueError:
            logging.error(f'[!] Invalid IP address: {ip_address}')
            raise argparse.ArgumentTypeError(f'Invalid IP address: {ip_address}')
    @staticmethod  
    def validate_interface(interface_name):
        interface = next((intrfc for intrfc in get_interfaces() if intrfc['name'] == interface_name), None)
        if not interface:
            logging.error(f'[!] Interface {interface_name} not found!')
            raise argparse.ArgumentTypeError(f'Interface {interface_name} not found!')
        return interface

def parse_args() -> argparse.Namespace:
    '''
    Parse command line arguments
    '''
    try:
        parser = argparse.ArgumentParser(
            description='ARP spoofing tool by d00m_r34p3r',
            formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=56)
        )
        parser.add_argument( 
            '-v', '--victim',
            metavar='victim_ip',
            type=Validation.validate_ip_address,
            required=True,
            help='ip adress of victim'
        )
        parser.add_argument( 
            '-g', '--gateway',
            metavar='gateway_ip',
            type=Validation.validate_ip_address,
            required=True,
            help='ip adress of gateway'
        )
        parser.add_argument( 
            '-i', '--interface',
            metavar='interface',
            required=True,
            help='interface to use for spoofing'
        )
        parser.add_argument( 
            '-V', '--verbose',
            action='store_true',
            help='print more information'
        )
         
    except Exception as ex:
        print_color(f'\n[!] {ex}', 'red')
        logging.error(f'[!] {ex}')
        input('\nPress Enter to continue...') 
        exit(1)
    
    return parser.parse_args()