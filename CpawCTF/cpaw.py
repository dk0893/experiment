import os, sys
import time
import argparse

def main( args ):
    
    print( f"main()" )

### Level1

# Q1. [Misc] Test Problem
# 
# cpaw{this_is_Cpaw_CTF} が提示されているので Submit するだけ

# Q6. [Crypto] Classical Cipher
# 
# シーザー暗号
def caesar( args ):
    
    # シーザー暗号とは、asciiコードで -3 した 文字にすること
    
    assert( len(args.args) >= 1 ), f"error: len(args.args)={len(args.args)}"
    
    print( f"args.args[0]={args.args[0]}" )
    
    result = []
    for cc in args.args[0]:
        
        if cc == '_':
            
            result.append( cc )
        
        else:
            
            assert( ord('A') <= ord(cc) <= ord('Z') or ord('a') <= ord(cc) <= ord('z') ), f"error: cc={cc}"
            
            assert( ord('A') <= ord(cc) - 3 <= ord('Z') or ord('a') <= ord(cc) - 3 <= ord('z') ), f"error: ord(cc)-3, cc={cc}"
            
            print( f"cc={cc} -> chr(ord(cc) - 3)={chr(ord(cc) - 3)}" )
            
            result.append( chr(ord(cc) - 3) )
    
    result = ''.join( result )
    
    print( f"result={result}" ) #=> result=Caesar_cipher_is_classical_cipher
    
    return result

# Q7. [Reversing] Can you execute ?
# 
# 実行ファイルなのでただ実行するだけ
# 
# $ file tenpu/exec_me
# tenpu/exec_me: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=663a3e0e5a079fddd0de92474688cd6812d3b550, not stripped
# $ tenpu/exec_me
# 
# cpaw{Do_you_know_ELF_file?}

# Q8. [Misc] Can you open this file ?
# 
# 以下のように、wordファイルっぽい、LibreOffice で開けた
# 
# $ file tenpu/open_me
# tenpu/open_me: Composite Document File V2 Document, Little Endian, Os: Windows, Version 10.0, Code page: 932, Author: v, Template: Normal.dotm, Last Saved By: v, Revision Number: 1, Name of Creating Application: Microsoft Office Word, Total Editing Time: 28:00, Create Time/Date: Mon Oct 12 04:27:00 2015, Last Saved Time/Date: Mon Oct 12 04:55:00 2015, Number of Pages: 1, Number of Words: 3, Number of Characters: 23, Security: 0
# 
# cpaw{Th1s_f1le_c0uld_be_0p3n3d}

# Q9. [Web] HTML Page
# 
# http://q9.ctf.cpaw.site/ をソース表示
# 
# cpaw{9216ddf84851f15a46662eb04759d2bebacac666}

# Q10. [Forensics] River
# 
# 画像ファイルを開くと緯度と経度が書かれていた、GoogleMapで探した
# 
# cpaw{koutsukigawa}

# Q11. [Network]pcap
# 
# network10.pcap
# 
# wiresharkで開くと、フラグがあった
# 
# cpaw{gochi_usa_kami}

# 
# Q12. [Crypto]HashHashHash!
# 
# Googleで検索したら、SHA-1 Center というサイト(データベース)があって、答えがあった
# 
# cpaw{Shal}

# Q14. [PPC]並べ替えろ!
# 
# ソート
def mysort( args ):
    
    # lst.sort() は、破壊的処理で、lst が書き換えられる
    # sorted(lst) は、ソート結果が返る (降順にしたければ sorted(lst, reverse=True) とする)
    
    lst = [15,1,93,52,66,31,87,0,42,77,46,24,99,10,19,36,27,4,58,76,2,81,50,102,33,94,20,14,80,82,49,41,12,143,121,7,111,100,60,55,108,34,150,103,109,130,25,54,57,159,136,110,3,167,119,72,18,151,105,171,160,144,85,201,193,188,190,146,210,211,63,207]
    
    result = ""
    for nn in sorted(lst, reverse=True):
        result += f"{nn}"
    
    print( result ) #=> 2112102072011931901881711671601591511501461441431361301211191111101091081051031021009994938785828180777672666360585755545250494642413634333127252420191815141210743210

### Level2

# Q13. [Stego]隠されたフラグ
# 
# モールス信号だった
# 
# cpaw{hidden_message:)}

# Q15. [Web] Redirect
# 
# 以下にアクセスするとき、リダイレクトされてて、Burp Suite で見たらヘッダに答えがあった
# 
# http://q15.ctf.cpaw.site/
# 
# cpaw{4re_y0u_1ook1ng_http_h3ader?}

# Q16. [Network+Forensic]HTTP Traffic
# 
# Wireshark で開いて、File→Export Objects→HTTP...→Save all で、保存
# HTMLとして開く、が動かない、ソースを見て、css、img、jsを正しいパスにすると動く
# 
# http_traffic.pcap
# 
# cpaw{Y0u_r3st0r3d_7his_p4ge}

# Q17. [Recon]Who am I ?
# 
# Google検索して、Twitterの画像を見たらわかる
# 
# cpaw{parock}

# Q18. [Forensic]leaf in forest
# 
# テキストファイルなので開いて、文字を探すだけ
# 
# misc100
# 
# cpaw{mgrep}

# Q19. [Misc]Image!
# 
# XMLとかが入ってる、ファイル名でGoogle検索すると、LibraOfficeで開けるファイルだった
# 
# misc100.zip
# 
# cpaw{It_is_fun__isn't_it?}

# Q20. [Crypto]Block Cipher
# 
# C言語を眺めて、コンパイルして、問題文"ruoYced_ehpigniriks_i_llrg_stae" と適当な数字を入れて実行した
# 1→2→3→4 と与えたときに、4で文章になってた
#   ⇒ ソースコードをちゃんと読むと、4 を入れるべきだったらしい
# 
# crypto100.c
# 
# cpaw{Your_deciphering_skill_is_great}

# Q21. [Reversing]reversing easy!
# 
# rev100をGhidraで逆コンパイル(rev100.c)、main関数だけ見て、
# asciiコード表をで変換する
# 
# rev100
# 
# cpaw{yakiniku!}

# Q22. [Web]Baby's SQLi - Stage 1-
# 
# SQLが実行できるテキストボックスがあるので、「select * from palloc_home」を
# 実行すると、答えがあった
# あと、next stage urlに「https://ctf.spica.bz/baby_sql/stage2_7b20a808e61c8573461cf92b1fe63b3f/index.php」が格納されてた
# 
# https://ctf.spica.bz/baby_sql/
# 
# cpaw{palloc_escape_from_stage1;(}

# Q28. [Network] Can you login？
# 
# pcapを見ると、FTPサーバにアクセスしたログだった。
# FTPサーバのIPアドレスと、ログインIDとパスワードがあったので、
# それを使って、ParrotOSでftpコマンドでログインした。
# ls -a で .hidden_flag_file が見つかったので、中に答えがあった
# 
# ※最初に WinSCP を使ったので全然見つからず、ftp に ls -a があることも初めて知った
# 
# network100_be557d01b0299a03dd3569893226dda424efc9a0.pcap
# 
# cpaw{f4p_sh0u1d_b3_us3d_in_3ncryp4i0n}

### Level3

# Q23. [Reversing]またやらかした！
# 
# rev200をGhidraで逆コンパイル(rev200.c)、main関数だけをコピーして、
# 少し体裁を整えて(rev200_l3_mine.c)、コンパイルした
# 実行すると、答えが出た
# 
# rev200
# 
# cpaw{vernam!!}

# Q24. [Web]Baby's SQLi - Stage 2-
# 
# Q22. の URL にアクセス。全然分からなかった。
# いろいろGoogle検索してたらSQLインジェクションという単語が見えてしまった
# 
# 「' OR 1=1--」を入力すればよい
# 
# cpaw{p@ll0c_1n_j@1l3:)}

# Q26. [PPC]Remainder theorem
# 
# 法の下での合同を理解して、力わざで解くプログラムを書いた
# 
# x ≡ 32134 (mod 1584891)
# x ≡ 193127 (mod 3438478)
# 
# x=35430270439 が出た
# 
# cpaw{35430270439}

def mymod( args ):
    
    # x ≡ 32134  (mod 1584891)
    # x ≡ 193127 (mod 3438478)
    
    alpha = 1584891
    be_ta = 3438478
    aa = bb = 1
    while True:
        tmp_a = alpha * aa + 32134
        tmp_b = be_ta * bb + 193127
        
        if tmp_a == tmp_b:
            print( f"x={tmp_a}" )
            break
        
        elif tmp_a > tmp_b:
            bb += 1
        
        else:
            aa += 1

# Q29. [Crypto] Common World
# 
# e と N が分かっていて、暗号文が提示されており、平文を求める問題。
# まずは、以下のところで原理を理解した。
# 
# https://it-trend.jp/encryption/article/64-0056
# 
# まずは、力わざで平文の総当たりをプログラムしたが、
# 全然ケタが増えていかなかった。
# 
# 次に、RsaCtfTool という解読ツールがあったので、使ってみた
# しかし、解読できない、という結果だった
# 
# 分からないので、ググると、eが小さいときは解読されるらしい。
# 
# 1つは、Low Public-Exponent Attack という解読方法。
# 暗号文(C)は平文(M)のe乗をNで割った余りなので、Mが小さいときは
# (Mのe乗がNより小さかったら)、単純にCのe乗根を求めればいい。
# しかし、Mは分かってないので、この解読ではダメだと思う。
# 
# もう1つは、Common Modulus Attack という解読方法。
# これは N が共通で、異なる e のとき、同じ平文(M)の暗号文があるとき、
# 解読できるというものだが、hint.txt を見ても、
# 同じ平文を暗号化したとは書いてない。
# 
# タイトルが Common World ということで、これが解法みたいだけど、
# うーん、って感じ。
# 
# Common Modulus Attack の原理は、
# e1s1 + e2s2 = 1 となるような s1、s2 が存在した場合、
# c1^s1*c2^s2=m^(e1s1)*m^(e2s2)=m^(e1s1+e2s2)=m^1=m とMが求まる。
# これはc1=m^e1を使ってるが、modしてないのはいいのか？
# 
# あと、N を素因数分解する(pとqが求まる)という解法があった。
# 通常は、これが現実的な時間で出来ないから成立してるわけだが、
# Nをpythonのbin(N)すると文字列が出てくる、これをlen()すると、
# 2800以上だった、これは2800以上bitのRSAであり、
# 普通は素因数分解できない(複数PCで512bitまでは素因数分解できるらしい)
# 1024bitの場合、10進数の桁数は300ぐらいらしい(4096bitで1000桁)
# 今回のNは870桁ぐらいだったので、絶対素因数分解できないはず
# 
# モヤモヤ問題だった
# 
# cpaw{424311244315114354}
def myrsa( args ):
    
    if args.args[0] == "ex":
        e = 5
        N = 35
        c = 17
    
    else:
        e = 11
        N = 236934049743116267137999082243372631809789567482083918717832642810097363305512293474568071369055296264199854438630820352634325357252399203160052660683745421710174826323192475870497319105418435646820494864987787286941817224659073497212768480618387152477878449603008187097148599534206055318807657902493850180695091646575878916531742076951110529004783428260456713315007812112632429296257313525506207087475539303737022587194108436132757979273391594299137176227924904126161234005321583720836733205639052615538054399452669637400105028428545751844036229657412844469034970807562336527158965779903175305550570647732255961850364080642984562893392375273054434538280546913977098212083374336482279710348958536764229803743404325258229707314844255917497531735251105389366176228741806064378293682890877558325834873371615135474627913981994123692172918524625407966731238257519603614744577
        c = 80265690974140286785447882525076768851800986505783169077080797677035805215248640465159446426193422263912423067392651719120282968933314718780685629466284745121303594495759721471318134122366715904
    
    rsa
    p = 0
    
    sta = time.time()
    
    while True:
        if ( p ** e ) % N == c:
            print( f"result: p={p}" )
            break
        
        else:
            p += 1
        
        if time.time() > sta + 60:
            sta += 60
            
            print( f"now: p={p}" )

def parse_args():
    
    parser = argparse.ArgumentParser( description='quantize.py' )
    
    parser.add_argument( '--ope',  default=None,            help='select operation, [None or ...]' )
    parser.add_argument( '--args', default=None, nargs='*', help='common list argument' )
    
    return parser.parse_args()

if __name__ == '__main__':
    
    args = parse_args()
    print( f"args={args}" )
    
    if args.ope == "caesar-cipher":
        
        # $ python cpaw.py --ope caesar-cipher --args fsdz
        # $ python cpaw.py --ope caesar-cipher --args Fdhvdu_flskhu_lv_fodvvlfdo_flskhu
        
        caesar( args )
    
    elif args.ope == "sort":
        
        # $ python cpaw.py --ope sort
        
        mysort( args )
    
    elif args.ope == "mod":
        
        # $ python cpaw.py --ope mod
        
        mymod( args )
    
    elif args.ope == "rsa":
        
        # $ python cpaw.py --ope rsa
        
        myrsa( args )
    
    else:
        
        main( args )

