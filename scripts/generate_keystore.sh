if [[ "$#" -ne 1 ]]; then
	echo "Usage: ./generate_keystore.sh <password>"
	exit 1
fi

size=${#1}

if [[ "$size" -lt 6 ]]; then
	echo "Password must have at least 6 characters!"
	exit 1
fi

echo "Generating keystore..."
keytool -genkey -alias clientkeystore \
    -keyalg RSA -keystore keystore.jks \
    -dname "CN=SEC Group, OU=SEC, O=MEIC, L=Lisbon, S=Lisbon, C=PT" \
    -storepass "$1" -keypass "$1"
echo "Saved 'keystore.jks' in current dir"
