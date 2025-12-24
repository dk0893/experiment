#!/bin/bash

#set -x # シェルスクリプト内で実際に実行されたコマンドを表示する (変数が使用されている場合は、その変数が展開された状態で表示される)
#set -v # シェルスクリプト内でこれから実行されるオプション (変数が使用されている場合は、-x オプションとは異なり、変数名がそのまま表示される)
set -e # 実行したコマンドの戻り値が 0 ではないステータスで終了した場合、即座に終了する

# コマンドライン引数1：名前を指定する → XXX と指定した場合、XXX.c をもとに、db_XXX を作る
# コマンドライン引数2：実行するクエリを指定する → 省略した場合、"cpp-examples/0.0.0/examples/XXX.ql"を実行する

CODEQL="../codeql"

if [ "$1" != "" ]; then
    NAME=$1
else
    NAME=
fi

if [ "$2" != "" ]; then
    QUERY=$2
else
    QUERY=${CODEQL}/qlpacks/codeql/cpp-examples/0.0.0/examples/${NAME}.ql
fi

if [ ${NAME} != "" ]; then
    
    # データベース作成
    ${CODEQL}/codeql database create ./db_${NAME} --overwrite -l c-cpp --command='gcc -c ./'${NAME}.c
    
    # クエリを実行
    ${CODEQL}/codeql query run ${QUERY} -d ./db_${NAME}
    
else
    
    echo "error: input name"
    
fi
