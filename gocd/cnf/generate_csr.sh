#!/usr/bin/env bash

SOURCE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"

if [ -f "$SOURCE_DIR/../roles/gocd_server/files/gocd.example.com.key" ] && 
   [ -f "$SOURCE_DIR/../roles/gocd_server/files/gocd.example.com.crt" ] && 
   [ -f "$SOURCE_DIR/../roles/gocd_agent/files/gocd.example.com.key" ] && 
   [ -f "$SOURCE_DIR/../roles/gocd_agent/files/gocd.example.com.crt" ]; then
   echo "certificates already generated"
   exit 0
fi   

openssl genrsa -out $SOURCE_DIR/gocd.example.com.key 2048
openssl req -new -key $SOURCE_DIR/gocd.example.com.key -config $SOURCE_DIR/gocd.example.com.cnf -out $SOURCE_DIR/gocd.example.com.csr
openssl x509 -req -days 365 -in $SOURCE_DIR/gocd.example.com.csr -signkey $SOURCE_DIR/gocd.example.com.key -out $SOURCE_DIR/gocd.example.com.crt

cp -r $SOURCE_DIR/gocd.example.com.{key,crt} $SOURCE_DIR/../roles/gocd_agent/files/
cp -r $SOURCE_DIR/gocd.example.com.{key,crt} $SOURCE_DIR/../roles/gocd_server/files/

rm $SOURCE_DIR/gocd.example.com.key $SOURCE_DIR/gocd.example.com.crt $SOURCE_DIR/gocd.example.com.csr