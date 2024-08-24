import os, sys
from scapy.all import *

from scapy_icmp import icmp
from scapy_common import detail

def myinfo():
    
    lst_if = get_if_list()
    
    print( f"get_if_list()={lst_if}" )
    
    lst_info = []
    
    for iface in lst_if:
        
        dic = { 'if': None, 'ip': None, 'mac': None, }
        
        dic['if']  = iface
        dic['ip']  = get_if_addr( iface )
        dic['mac'] = get_if_hwaddr( iface )
        
        lst_info.append( dic )
    
    for dic in lst_info:
        
        print( f"iface={dic['if']}" )
        print( f"  ip_addr={dic['ip']}" )
        print( f"  mac={dic['mac']}" )

def hostinfo( host ):
    
    res = icmp( host )
    
    mac = getmacbyip( res[IP].src )
    
    print( f"host({host}) mac={mac}" )

if __name__ == '__main__':
    
    # 実行例
    # sudo python scapy_info.py example.jp
    
    print( f"sys.argv={sys.argv}" )
    
    myinfo()
    
    print()
    
    hostinfo( sys.argv[1] )
