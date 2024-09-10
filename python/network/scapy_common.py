import os, sys
from scapy.all import *

def detail( pkt ):
    
    print()
    
    print( "--- show ---\n" )
    
    pkt.show()
    
    print( "--- ls ---\n" )
    
    ls( pkt )
    
    print( "\n--- hexdump ---\n" )
    
    hexdump( pkt )

if __name__ == '__main__':
    
    # 実行例
    # sudo python scapy_common.py
    
    print( f"sys.argv={sys.argv}" )
    
    detail( IP() )
