import os, sys
import argparse
import shutil
import base64
import struct
import datetime

### ファイル読み込み、書き込み

def fread_line( fpath ):
    
    lst = []
    with open(fpath) as ff:
        for line in ff:
            lst.append( line.rstrip('\n') )
    
    return lst

def fread_bin( fpath ):
    
    # バイナリファイルを読み出し → bytes型
    
    with open(fpath, 'rb') as ff:
        data = ff.read() # 引数(サイズ)を省略すると全データ読み出し
    
    return data

def fwrite_bin( fpath, data ):
    
    # bytes型をバイナリファイルを書き込み
    
    with open(fpath, 'wb') as ff:
        ff.write( data )

### ファイルシステム

def listdir( dpath ):
    
    files = os.listdir( dpath )
    print( files )

# unzip
def unzip( fpath ):
    
    shutil.unpack_archive( fpath )
    os.remove( fpath )

### encode と decode

# 
# >>> ee = "バイナリ解析".encode()
# >>> ee
# b'\xe3\x83\x90\xe3\x82\xa4\xe3\x83\x8a\xe3\x83\xaa\xe8\xa7\xa3\xe6\x9e\x90'
# >>> ee.hex()
# 'e38390e382a4e3838ae383aae8a7a3e69e90'
# >>> ee.hex(" ")
# 'e3 83 90 e3 82 a4 e3 83 8a e3 83 aa e8 a7 a3 e6 9e 90'
# >>> ee.decode()
# 'バイナリ解析'
# 

def str2int( ss, offset=0, num_disable=False ):
    
    # $ python common.py --ope str2int --arg 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
    # > str2int=[48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122]
    # > str2int=['0x30', '0x31', '0x32', '0x33', '0x34', '0x35', '0x36', '0x37', '0x38', '0x39', '0x41', '0x42', '0x43', '0x44', '0x45', '0x46', '0x47', '0x48', '0x49', '0x4a', '0x4b', '0x4c', '0x4d', '0x4e', '0x4f', '0x50', '0x51', '0x52', '0x53', '0x54', '0x55', '0x56', '0x57', '0x58', '0x59', '0x5a', '0x61', '0x62', '0x63', '0x64', '0x65', '0x66', '0x67', '0x68', '0x69', '0x6a', '0x6b', '0x6c', '0x6d', '0x6e', '0x6f', '0x70', '0x71', '0x72', '0x73', '0x74', '0x75', '0x76', '0x77', '0x78', '0x79', '0x7a']
    
    # ワンライナー
    # $ python -c 'print([f"0x{ord(cc):02X}" for cc in list("picoCTF{")])'
    # > ['0x70', '0x69', '0x63', '0x6F', '0x43', '0x54', '0x46', '0x7B']
    # $ python -c 'print(list(reversed([f"0x{ord(cc):02X}" for cc in list("picoCTF{")])))'
    # > ['0x7B', '0x46', '0x54', '0x43', '0x6F', '0x63', '0x69', '0x70']
    
    lst = []
    for cc in ss:
        
        if cc == ' ':
            lst.append( ord(cc) )
        
        elif ('0' <= cc <= '9') and not num_disable:
            mm = (ord(cc) - ord('0') + offset) % (ord('9') - ord('0') + 1)
            lst.append( mm + ord('0') )
        
        elif 'A' <= cc <= 'Z':
            mm = (ord(cc) - ord('A') + offset) % (ord('Z') - ord('A') + 1)
            lst.append( mm + ord('A') )
        
        elif 'a' <= cc <= 'z':
            mm = (ord(cc) - ord('a') + offset) % (ord('z') - ord('a') + 1)
            lst.append( mm + ord('a') )
        
        else:
            
            lst.append( ord(cc) )
    
    print( f"str2int={lst}" )
    print( f"str2int={[hex(ii) for ii in lst]}" )
    
    return lst

def str2chr( ss ):
    
    # python common.py --ope str2chr --arg 7069636f4354467b5539585f556e5034636b314e365f42316e345233535f39343130343638327d
    # > picoCTF{U9X_UnP4ck1N6_B1n4R3S_94104682}
    
    lst_ret = []
    ii = 0
    while True:
        
        lst_ret.append( chr(int(ss[ii:ii+2], base=16)) )
        
        ii += 2
        
        if ii >= len(ss):
            break
    
    return ''.join( lst_ret )

def int2chr( lst ):
    
    # $ python common.py --ope int2chr --arg 48 49 50 51 52 53 54 55 56 57 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 97 98 99 100 101 102 103 104 105 106 107 108 109 110 111 112 113 114 115 116 117 118 119 120 121 122
    # > int2chr=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
    
    # ワンライナー
    # $ python -c 'hh="7069636f4354467b6178386d433052553676655f4e5838356c346178386d436c5f38356462643231357d"; print("".join([chr(int(hh[ii] + hh[ii+1], base=16)) for ii in range(0, len(hh), 2)]))'
    # > picoCTF{ax8mC0RU6ve_NX85l4ax8mCl_85dbd215}
    
    ss = ""
    lst_ret = []
    for ii in lst:
        ss += chr(ii)
        lst_ret.append( chr(ii) )
    
    #print( lst_ret )
    print( f"int2chr={ss}" )
    
    return lst_ret

def long2chr( lst ):
    
    # $ python -c 'import struct; print(struct.pack("<QQQ",0x7b4654436f636970,0x47414c4647414c46,0x7d47414c46))'
    # b'picoCTF{FLAGFLAGFLAG}\x00\x00\x00'
    
    # python common.py --ope long2chr --arg 0x7b4654436f636970 0x47414c4647414c46 0x7d47414c46
    # > b'picoCTF{FLAGFLAGFLAG}\x00\x00\x00'
    
    return struct.pack( "<" + "Q" * len(lst), *lst )

def from_timestamp( val ):
    
    # $ python common.py --ope from_timestamp --arg 1700513181
    # > 2023-11-21 05:46:21
    
    ss = datetime.datetime.fromtimestamp( val )
    
    print( ss )
    
    return ss

def base64_encode( ss ):
    
    # 2進数にして、6bitずつに分割し、変換表で変換する
    # a-zA-Z0-9 と + / の計64文字で表すエンコード方式
    # 6bit に満たない場合は 0 を足す
    # 4文字に満たない場合は = を足す
    
    bss = ss.encode( 'utf-8' )
    
    ret = base64.b64encode( bss )
    
    print( ret )

def base64_decode( ss ):
    
    # 76文字を変換表で逆変換すると6bit×76文字=456bit(57byte)となる
    
    # Z：011001
    # G：000110
    # 0x64 は、d となる
    
    bdec = base64.b64decode( ss )
    
    print( bdec )

def base64_encode_manual( ss ):
    
    print( f"len(ss)={len(ss)}" )
    
    table = {
        "000000": 'A', "000001": 'B', "000010": 'C', "000011": 'D',
        "000100": 'E', "000101": 'F', "000110": 'G', "000111": 'H',
        "001000": 'I', "001001": 'J', "001010": 'K', "001011": 'L',
        "001100": 'M', "001101": 'N', "001110": 'O', "001111": 'P',
        "010000": 'Q', "010001": 'R', "010010": 'S', "010011": 'T',
        "010100": 'U', "010101": 'V', "010110": 'W', "010111": 'X',
        "011000": 'Y', "011001": 'Z', "011010": 'a', "011011": 'b',
        "011100": 'c', "011101": 'd', "011110": 'e', "011111": 'f',
        "100000": 'g', "100001": 'h', "100010": 'i', "100011": 'j',
        "100100": 'k', "100101": 'l', "100110": 'm', "100111": 'n',
        "101000": 'o', "101001": 'p', "101010": 'q', "101011": 'r',
        "101100": 's', "101101": 't', "101110": 'u', "101111": 'v',
        "110000": 'w', "110001": 'x', "110010": 'y', "110011": 'z',
        "110100": '0', "110101": '1', "110110": '2', "110111": '3',
        "111000": '4', "111001": '5', "111010": '6', "111011": '7',
        "111100": '8', "111101": '9', "111110": '+', "111111": '/',
    }
    
    # decode のつもりで間違えて作ってた (なので途中まで)
    
    # 1文字ずつ整数に直して2進数化して8bitずつを連結
    ret = ""
    for cc in ss:
        ret += f"{ord(cc):08b}" # 8bitを連結
    
    print( f"len(ret)={len(ret)}, ret={ret}" )
    
    ret2 = ""
    idx = 0
    while idx + 6 <= len(ret):
        ret2 += table[ ret[idx:idx+6] ]
        idx += 6
    
    if idx < len(ret):
        tmp = ret[idx:] + "0" * (len(ret) - idx)
        ret2 += table[tmp]
    
    if len(ret2) % 4 != 0:
        ret2 += "=" * (4 - len(ret2) % 4)
    
    print( f"len(ret)={len(ret2)}, ret={ret2}" )

def base64_decode_manual( ss ):
    
    # $ python common.py --ope base64_decord_manual --arg "YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6ZzVNR3N5TXpjNWZRPT0nCg=="
    # > len(ss)=72
    # > ii=51, nn=0A
    # > len(ret)=51, ret=b'd3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzg5MGsyMzc5fQ=='
    
    print( f"len(ss)={len(ss)}" )
    
    table = {
        'A': "000000", 'B': "000001", 'C': "000010", 'D': "000011",
        'E': "000100", 'F': "000101", 'G': "000110", 'H': "000111",
        'I': "001000", 'J': "001001", 'K': "001010", 'L': "001011",
        'M': "001100", 'N': "001101", 'O': "001110", 'P': "001111",
        'Q': "010000", 'R': "010001", 'S': "010010", 'T': "010011",
        'U': "010100", 'V': "010101", 'W': "010110", 'X': "010111",
        'Y': "011000", 'Z': "011001", 'a': "011010", 'b': "011011",
        'c': "011100", 'd': "011101", 'e': "011110", 'f': "011111",
        'g': "100000", 'h': "100001", 'i': "100010", 'j': "100011",
        'k': "100100", 'l': "100101", 'm': "100110", 'n': "100111",
        'o': "101000", 'p': "101001", 'q': "101010", 'r': "101011",
        's': "101100", 't': "101101", 'u': "101110", 'v': "101111",
        'w': "110000", 'x': "110001", 'y': "110010", 'z': "110011",
        '0': "110100", '1': "110101", '2': "110110", '3': "110111",
        '4': "111000", '5': "111001", '6': "111010", '7': "111011",
        '8': "111100", '9': "111101", '+': "111110", '/': "111111",
    }
    
    # 1文字ずつ逆変換して6bitを連結する
    ret = ""
    for cc in ss:
        if cc == "=":  # = が来たら終了
            break
        ret += table[cc] # 逆変換した6bitを連結
    
    # 前から 8bit ずつで文字列を作る
    lst = []
    idx = 0
    while idx + 8 <= len(ret):
        lst.append( int(ret[idx:idx+8], base=2) ) # 2進数を10進数に変換して格納
        idx += 8
    
    # 余った分は 0 のはず
    assert int(ret[idx:], base=2) == 0, f"ret[idx:]={ret[idx:]}"
    
    ret = ""
    for ii, nn in enumerate(lst):
        if nn < 0x20 or nn >= 0x7F:
            print( f"ii={ii}, nn={nn:02X}" )
        else:
            ret += chr(nn)
    
    print( f"len(ret)={len(ret)}, ret={ret}" )

def base64_decode_file( fpath ):
    
    #with open( fpath, 'rb' ) as ff:
    #    bss = ff.read()
    
    lst = fread_line( fpath )
    
    bss = b''
    for ll in lst:
        bss += ll.encode( 'utf-8' )
    
    print( bss )
    
    bdec = base64.b64decode( bss )
    
    print( bdec )
    
    with open( fpath + ".out", 'wb' ) as ff:
        ff.write( bdec )

def morse_code( lst, dot='x', dash='y', sep=' ' ):
    
    # 短点(・)は dot、長点(－)は dash、quarter-chord point
    
    dic = { 'dq': 'A', 'qddd': 'B', 'qdqd': 'C', 'qdd': 'D', 'd': 'E', 'ddqd': 'F', 'qqd': 'G', 'dddd': 'H',
            'dd': 'I', 'dqqq': 'J', 'qdq': 'K', 'dqdd': 'L', 'qq': 'M', 'qd': 'N', 'qqq': 'O', 'dqqd': 'P',
            'qqdq': 'Q', 'dqd': 'R', 'ddd': 'S', 'q': 'T', 'ddq': 'U', 'dddq': 'V', 'dqq': 'W', 'qddq': 'X',
            'qdqq': 'Y', 'qqdd': 'Z', 'dqqqq': '1', 'ddqqq': '2', 'dddqq': '3', 'ddddq': '4', 'ddddd': '5',
            'qdddd': '6', 'qqddd': '7', 'qqqdd': '8', 'qqqqd': '9', 'qqqqq': '0', 'dqdqdq': '.',
            'qqddqq': ',', 'qqqddd': ':', 'ddqqdd': '?', 'ddqqdq': '_', 'dqdqd': '+', 'qddddq': '-',
            'qddq': 'x', 'dddddd': '^', 'qddqd': '/', 'dqqdqd': '@', 'qdqqd': '(', 'qdqqdq': ')',
            'dqddqd': '"', 'dqqqqd': '\'', }
    
    idx = 0
    ret = []
    while idx < len(lst):
        
        dd = lst[idx]
        assert dd == sep or dd == dot or dd == dash, f"dd={dd:X}, lst={lst}"
        
        if dd == sep:
            continue
        
        ll = []
        while idx < len(lst):
            
            if lst[idx] == sep:
                break
            elif lst[idx] == dot:
                ll.append( 'd' )
            else: # dash
                ll.append( 'q' )
            
            idx += 1
        
        idx += 1
        
        if len(ll) == 0:
            # 2連続区切り文字
            print( f"error: double separator, idx={idx}" )
            return -1
        
        ret.append( ''.join(ll) )
    
    ss = ""
    for rr in ret:
        if rr not in dic:
            print( f"not match: rr={rr}, ss={ss}" )
            return -1
        ss += dic[rr]
    
    return ss

def morse_code_bin( fpath, fmt='utf-8' ):
    
    # バイナリファイルを読み出し → bytes型
    data = fread_bin( fpath )
    
    idx = 0
    lst = []
    while True:
        
        dd = data[idx]
        assert 0 <= dd <= 0xFF, f"fatal: dd={dd:X}" 
        
        # 1byteずつ処理
        
        if dd < 0x80:
            
            # ASCII
            lst.append( data[idx] )
        
        else:
            
            if fmt == 'utf-8':
                
                if (dd & 0xE0) == 0xC0:
                    # 2byte
                    lst.append( (data[idx] << 8) | data[idx+1] )
                    idx += 1
                
                elif (dd & 0xF0) == 0xE0:
                    # 3byte
                    lst.append( (data[idx] << 16) | (data[idx+1] << 8) | data[idx+2] )
                    idx += 2
                
                elif (dd & 0xF8) == 0xF0:
                    # 4byte
                    lst.append( (data[idx] << 24) | (data[idx+1] << 16) | (data[idx+2] << 8) | data[idx+3] )
                    idx += 3
        
        idx += 1
        
        if idx >= len(data):
            break
    
    print( f"lst={[hex(ii) for ii in lst]}" )
    
    ret = morse_code( lst, dot=0xE2808B, dash=0xE2808C, sep=0x5A )
    if ret == -1:
        raise
    
    print( f"ret={ret}" )

def endian( fpath, fpath_out ):
    
    # $ python common.py --ope endian --fpath ../picoCTF/picoCTF2024_Forensics/challengefile --fpath_out ../picoCTF/picoCTF2024_Forensics/challengefile.jpg
    
    data = fread_bin( fpath )
    
    if len(data) % 4 != 0:
        data += b'0' * (4 - len(data) % 4)
    assert len(data) % 4 == 0, "fatal"
    
    bret = b''
    ii = 0
    while ii + 4 <= len(data):
        
        tmp = struct.unpack( '<I', data[ii:ii+4] )
        bret += struct.pack( '>I', tmp[0] )
        
        ii += 4
    
    fwrite_bin( fpath_out, bret )

def is_prime( num ):
    
    # 指定の数(num)が自分以外で割り切れる数が無ければ素数
    for ii in range( 2, num ): #num + 1 ):
        if num % ii == 0:
            return False
    
    return True

def nth_prime( nth ):
    
    cnt = 0
    
    ii = 2
    while cnt < nth:
        if is_prime( ii ):
            cnt += 1
        ii += 1
    
    print( f"ii={ii-1}, cnt={cnt}" )

def is_prime_trial_division( num, primes ):
    
    for pp in primes:
        if num % pp == 0:
            return False
    
    primes.append( num )
    
    return True

def nth_prime_trial_division( nth ):
    
    cnt = 0
    primes = []
    
    ii = 2
    while cnt < nth:
        if is_prime_trial_division( ii, primes ):
            cnt += 1
        ii += 1
    
    print( f"ii={ii-1}, cnt={cnt}" )

def parse_args():
    
    parser = argparse.ArgumentParser( description='baby_stack' )
    
    parser.add_argument( '--ope',       default=None,            help='select operation, [None or ...]' )
    parser.add_argument( '--fpath',     default=None,            help='input file path' )
    parser.add_argument( '--fpath_out', default=None,            help='output file path' )
    parser.add_argument( '--arg',       default=None, nargs='*', help='input file path' )
    parser.add_argument( '--debug',     action='store_true',     help='debug' )
    
    return parser.parse_args()

if __name__ == '__main__':
    
    args = parse_args()
    print( f"args={args}" )
    
    if args.ope is None:
        
        raise
    
    elif args.ope == "unzip":
        
        fpath = args.fpath
        
        # unzip
        assert fpath is not None, "need fpath"
        
        dname = os.path.dirname( fpath )
        print( f"dname={dname}" )
        
        files = os.listdir( dname )
        print( f"files={files}" )
        
        basename, ext = os.path.splitext( fpath )
        print( f"basename={basename}, ext={ext}" )
        
        # unzip and remove
        unzip( fpath )
    
    elif args.ope == "str2int":
        
        # $ python common.py --ope str2int --arg 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
        # > str2int=[48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122]
        # > str2int=['0x30', '0x31', '0x32', '0x33', '0x34', '0x35', '0x36', '0x37', '0x38', '0x39', '0x41', '0x42', '0x43', '0x44', '0x45', '0x46', '0x47', '0x48', '0x49', '0x4a', '0x4b', '0x4c', '0x4d', '0x4e', '0x4f', '0x50', '0x51', '0x52', '0x53', '0x54', '0x55', '0x56', '0x57', '0x58', '0x59', '0x5a', '0x61', '0x62', '0x63', '0x64', '0x65', '0x66', '0x67', '0x68', '0x69', '0x6a', '0x6b', '0x6c', '0x6d', '0x6e', '0x6f', '0x70', '0x71', '0x72', '0x73', '0x74', '0x75', '0x76', '0x77', '0x78', '0x79', '0x7a']
        
        str2int( args.arg[0] )
    
    elif args.ope == "str2chr":
        
        # python common.py --ope str2chr --arg 7069636f4354467b5539585f556e5034636b314e365f42316e345233535f39343130343638327d
        
        print( str2chr(args.arg[0]) )
    
    elif args.ope == "int2chr":
        
        # $ python common.py --ope int2chr --arg 48 49 50 51 52 53 54 55 56 57 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 97 98 99 100 101 102 103 104 105 106 107 108 109 110 111 112 113 114 115 116 117 118 119 120 121 122
        # > int2chr=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
        
        lst = [ int(ii) for ii in args.arg ]
        
        int2chr( lst )
    
    elif args.ope == "long2chr":
        
        # python common.py --ope long2chr --arg 0x7b4654436f636970 0x47414c4647414c46 0x7d47414c46
        # > b'picoCTF{FLAGFLAGFLAG}\x00\x00\x00'
        
        lst = [ int(ii, base=16) for ii in args.arg ]
        
        print( long2chr(lst) )
    
    elif args.ope == "caesar_cipher":
        
        lst = str2int( args.arg[0], int(args.arg[1]), num_disable=True )
        
        lst_ret = int2chr( lst )
    
    elif args.ope == "from_timestamp":
        
        # $ python common.py --ope from_timestamp --arg 1700513181
        # > 2023-11-21 05:46:21
        
        from_timestamp( int(args.arg[0], base=10) )
    
    elif args.ope == "base64_encord":
        
        # $ python common.py --ope base64_encord --arg "deep insider"
        # b'ZGVlcCBpbnNpZGVy'
        
        base64_encode( args.arg[0] )
    
    elif args.ope == "base64_decord":
        
        # $ python common.py --ope base64_decord --arg "ZGVlcCBpbnNpZGVy"
        # b'deep insider'
        
        base64_decode( args.arg[0] )
    
    elif args.ope == "base64_encord_manual":
        
        # $ python common.py --ope base64_encord_manual --arg "b'd3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzg5MGsyMzc5fQ=='"
        
        base64_encode_manual( args.arg[0] )
    
    elif args.ope == "base64_decord_manual":
        
        # $ python common.py --ope base64_decord_manual --arg "YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6ZzVNR3N5TXpjNWZRPT0nCg=="
        
        base64_decode_manual( args.arg[0] )
    
    elif args.ope == "base64_decord_file":
        
        # $ python common.py --ope base64_decord --fpath ../ksnctf/Onion.txt
        # b'deep insider'
        
        base64_decode_file( args.fpath )
    
    elif args.ope == "morse_code_bin":
        
        # $ python common.py --ope morse_code_bin --fpath ../setodaNoteCTF/Misc/morse_zero.txt
        
        morse_code_bin( args.fpath )
    
    elif args.ope == "endian":
        
        # $ python common.py --ope endian --fpath ../picoCTF/picoCTF2024_Forensics/challengefile --fpath_out ../picoCTF/picoCTF2024_Forensics/challengefile.jpg
        
        endian( args.fpath, args.fpath_out )
    
    elif args.ope == "prime":
        
        # $ python common.py --ope prime --arg 72057594037927936
        
        #nth_prime( int(args.arg[0]) )
        nth_prime_trial_division( int(args.arg[0]) )
    
    else:
        raise
