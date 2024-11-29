import os, sys
import argparse
import logging

from scapy.all import *

def memo( pkts ):
    
    print( "--- summary ---" )
    
    pkts.summary()

def main( args ):
    
    if args.pcap is not None:
        
        pkts = rdpcap( args.pcap )
        
        logging.info( f"pkts={pkts}, len(pkts)={len(pkts)}" )
    
    if args.ope is None:
        
        memo( args )
    
    elif args.ope == "logger":
        
        # $ python main.py --ope logger --pcap logger.pcap
        
        old_host   = None
        old_device = None
        for ii, pp in enumerate(pkts):
            
            now = pp.load
            dir = now[16] & 0x01
            
            if dir:
                # device → host
                if old_device is not None:
                    assert old_device[ 0: 2] == now[ 0: 2], f"ii={ii:02d}d: old_device=\n{old_device.hex()}\nnow=\n{now.hex()}"
                    assert old_device[10:27] == now[10:27], f"ii={ii:02d}d: old_device=\n{old_device.hex()}\nnow=\n{now.hex()}"
                
                if (ii % 4) == 0:
                    assert now[2:10].hex() == "a00aefbe83bfffff", f"ii={ii:04d}d:  ID={now[2:10].hex()}"
                else:
                    assert now[2:10].hex() == "a0faeebe83bfffff", f"ii={ii:04d}d:  ID={now[2:10].hex()}"
                    logging.debug( f"ii={ii:04d}d: ID={now[2:10].hex()}, now[27:].hex()={now[27:].hex()}" )
                
                
                old_device = now
            
            else:
                # host → device
                if old_host is not None:
                    assert old_host[0:2] == now[0:2], f"ii={ii:02d}h: old_host=\n{old_host.hex()}\nnow=\n{now.hex()}"
                    assert old_host[10:] == now[10:], f"ii={ii:02d}h: old_host=\n{old_host.hex()}\nnow=\n{now.hex()}"
                
                if (ii % 4) == 1:
                    assert now[2:10].hex() == "a00aefbe83bfffff", f"ii={ii:04d}d:  ID={now[2:10].hex()}"
                else:
                    assert now[2:10].hex() == "a0faeebe83bfffff", f"ii={ii:04d}d:  ID={now[2:10].hex()}"
                
                #logging.debug( f"ii={ii:04d}h, now={now.hex()}" )
                
                old_host = now

def parse_args():
    
    parser = argparse.ArgumentParser( description='Scapy program' )
    
    parser.add_argument( '--ope',   default=None, help='select operation, [None or ...]' )
    parser.add_argument( '--pcap',  default=None, help='input pcap file' )
    parser.add_argument( '--debug', action='store_true', help='debug' )
    
    return parser.parse_args()

if __name__ == '__main__':
    
    args = parse_args()
    print( f"args={args}" )
    
    if args.debug:
        logname = os.path.basename( sys.argv[0] )
        logname = os.path.splitext(logname)[0] + ".log"
        if os.path.isfile( logname ):
            os.remove( logname )
        logging.basicConfig( level=logging.DEBUG, handlers=[logging.FileHandler(logname), logging.StreamHandler(sys.stdout)] )
    else:
        logging.basicConfig( level=logging.INFO )
    
    main( args )
