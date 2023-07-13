from colorama import init

from modules.print import *
from modules.args import parse_args
from modules.arp import Arp

import os
import datetime
import logging

def start_log() -> None:
    '''
    Start logging and report errors to log file
    '''
    log_directory = 'logs'
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)
    logging.basicConfig(level=logging.DEBUG, filename=f"logs/arp_errors_{datetime.datetime.now().strftime('%d%m%Y')}.log", filemode='a', encoding='utf-8')

if __name__ == '__main__':
    init()
    start_log()
    print_logo()
    args = parse_args()
    
    arp = Arp(args.victim, args.gateway, args.interface, args.count, args.verbose)
    arp.run()
    
    