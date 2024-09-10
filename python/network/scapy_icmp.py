import os, sys
from scapy.all import *

from scapy_common import detail

def icmp( host="localhost", debug=False ):
    
    pkt = IP(dst=host)/ICMP()
    
    print( f"pkt={pkt}" )
    
    if debug: detail( pkt )
    
    res = sr1( pkt )
    
    print( f"res={res}" )
    
    if debug: detail( res )
    
    return res

if __name__ == '__main__':
    
    # 実行例
    # $ sudo python scapy_icmp.py example.jp
    
    print( f"sys.argv={sys.argv}" )
    
    icmp( sys.argv[1] )
