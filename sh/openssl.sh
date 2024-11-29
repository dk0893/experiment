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

if [ "$OPE" = "" ]; then
    exit 1
else # LATEST
    
    # バージョン表示
    openssl version
    
    # 
    
    
    
    
    
    
fi

DATE=`date '+%Y/%m/%d %H:%M:%S'`
echo ${DATE} "end"
