import random
import time
from pwn import *

def get_random(length, seed):
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    random.seed(seed)  # seeding with current time 
    s = ""
    for i in range(length):
        s += random.choice(alphabet)
    return s

def main(delay):
    
    adrs = "verbal-sleep.picoctf.net"
    port = 64908
    #adrs = "localhost"
    #port = 4000
    
    proc = remote( adrs, port )
    
    now = time.time()
    
    try:
        n = 0
        while n < 50:
            
            ret = proc.recvuntil( ':' )
            
            seed = int((now) * 1000) + n + delay
            #seed = int((now) * 1000)
            
            info( f"recv ret={ret}', seed={seed}" )
            
            ss = get_random( 20, seed )
            
            proc.sendline( ss.encode("utf-8") )
            ret = proc.recvline()
            info( f"send ss={ss}, recv ret={ret}" )
            if 'Congratulations' in ret.decode("utf-8"):
                info( proc.recvline() )
                info( proc.recvline() )
                info( proc.recvline() )
                info( proc.recvline() )
            
            n += 1
    
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting the program...")
    except EOFError:
        print( f"********* ret={ret} *********" )

if __name__ == "__main__":
    for ii in range(1000):
        main( ii * 30 )
