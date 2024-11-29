#!/bin/bash

#set -x # シェルスクリプト内で実際に実行されたコマンドを表示する (変数が使用されている場合は、その変数が展開された状態で表示される)
#set -v # シェルスクリプト内でこれから実行されるオプション (変数が使用されている場合は、-x オプションとは異なり、変数名がそのまま表示される)
set -e # 実行したコマンドの戻り値が 0 ではないステータスで終了した場合、即座に終了する

DATE=`date '+%Y/%m/%d %H:%M:%S'`
echo ${DATE} "start"

if [ "$1" != "" ]; then
    OPE=$1
else
    OPE=LATEST
fi

if [ "$2" != "" ]; then
    FNAME=$2
else
    FNAME="not found"
fi

sub()
{
    echo $1
    echo $2
}

if [ "$OPE" = "2to10" ]; then
    # seq 覚書
    # seq x：1からxまでを出力
    # seq x y：xからyまでを出力
    # seq x y z：xからzまでyずつ増やした数を出力（増分は負値も可）
    # for 覚書
    # 単純に文字列のリストとして並べる
    # {1..10} として1から10までのループにできる
    for CNT in `seq 2 1 10`
    do
        echo $CNT
    done
    exit 1
elif [ "$OPE" = "sub" ]; then
    sub 1 2
elif [ "$OPE" = "count" ]; then
    # ファイルが存在することを確認してから処理を行う
    if [ -e "${FNAME}" ]; then
        echo File exists: ${FNAME}
        # ファイルの行数を出力する
        # wc -l ${FNAME} は、行数以外が出力されてしまう
        cat ${FNAME} | wc -l 
    fi
elif [ "OPE" = "sedsample" ]; then
    # sed 覚書
    # echo -e は改行を有効にする
    # sed の2つ目は空行削除
    echo -e "aaa,bbb,ccc\n \nddd,eee,fff" | sed -e 's/,//g' | sed -e '/^$/d'
elif [ "OPE" = "awksample" ]; then
    # awk 覚書
    # awk -F は区切り文字の変更
    # awk の NR は行番号(1始まり)、NF は列番号(1始まり
    echo -e "aaa,bbb,ccc\r\nddd,eee,fff" | awk -F, 'BEGIN {ll=0} {printf "%02d: %s %d\n", NR, $1, ll; ll+=1}'
else # LATEST
    # ファイルが存在することを確認してから1行ずつ読み出す
    if [ -e "${FNAME}" ]; then
        echo File exists: ${FNAME}
        while read LINE
        do
            echo $LINE
        done < ${FNAME}
    else
        echo "file is not found"
    fi
fi

DATE=`date '+%Y/%m/%d %H:%M:%S'`
echo ${DATE} "end"
