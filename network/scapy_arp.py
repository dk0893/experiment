import os, sys
from scapy.all import *

from scapy_common import detail

def arp( ipaddr="127.0.0.1", debug=False ):
    
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipaddr)
    
    print( f"pkt={pkt}" )
    
    if debug: detail( pkt )
    
    res = srp1( pkt )
    
    print( f"res={res}" )
    
    if debug: detail( res )
    
    return res

if __name__ == '__main__':
    
    # 実行例
    # $ sudo python scapy_arp.py 10.0.2.2
    
    print( f"sys.argv={sys.argv}" )
    
    arp( sys.argv[1] )
