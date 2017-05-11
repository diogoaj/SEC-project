#!/bin/sh

if [[ "$#" -ne 2 ]]; then
	echo "Usage: ./generate_keystore.sh <password> <id>"
	exit 1
fi

size=${#1}

if [[ "$size" -lt 6 ]]; then
	echo "Password must have at least 6 characters!"
	exit 1
fi

echo "Generating keystore..."
keytool -genkey -alias serverkeystore \
    -keyalg RSA -keystore keystore_$2.jks \
    -dname "CN=SEC Group, OU=SEC, O=MEIC, L=Lisbon, S=Lisbon, C=PT" \
    -storepass "$1" -keypass "$1"
echo "Saved 'keystore.jks' in current dir"

echo "Exporting certificate from keystore"
keytool -export -alias serverkeystore -file certificate_$2.crt -keystore keystore_$2.jks -storepass "$1" -keypass "$1"
echo "Done"

mv keystore_$2.jks ../ServerSide/src/main/resources
mv certificate_$2.crt ../ClientSide/src/main/resources