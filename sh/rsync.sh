#!/usr/bin/env bash
set -e

read -p "remote host [default 39.105.199.190]: " r_host
read -p "remote user [default root]: " r_user
read -p "remote path [default ~/test/]: " r_path

if [ -z $r_user ]; then
    r_user="root"
fi

if [ -z $r_path ]; then
    r_path="~/test/"
fi

if [ -z $r_host ]; then
    r_host="39.105.199.190"
fi


tmpvar=$(realpath $0)
echo $tmpvar
PROJECT_DIR=${tmpvar%/sh*}
echo $PROJECT_DIR
if [ -n ${PROJECT_DIR} ] ; then
    cmd="cd ${PROJECT_DIR} && rsync -avzu . --exclude-from=\"${tmpvar%/*}/.ignore\"  \"$r_user@$r_host:${r_path}\""
fi
echo $cmd
eval $cmd
