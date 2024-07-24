CA_DIR=certs/ca
SRV_DIR=certs/server

CANAME=ca
MYCERT=server

PASSPHRASE=supapass
SRV_HOSTNAME='localhost'
SRV_IP='127.0.0.1'

rm -rf $CA_DIR/*
rm -rf $SRV_DIR/*

echo "Generating CA key..."

# generate aes encrypted private key
openssl genrsa -aes256 -out "$CA_DIR/$CANAME.key" --passout pass:$PASSPHRASE 4096

echo "Generating CA certificate..."

# create certificate, 1826 days = 5 years
openssl req -x509 -new -nodes -key "$CA_DIR/$CANAME.key" -sha256 -days 1826 -out "$CA_DIR/$CANAME.crt" -quiet -subj '/CN=DiplomskiCA/C=RS/ST=Serbia/L=Serbia/O=ETF' --passin pass:$PASSPHRASE

echo "Generating Server certificate..."
# create server cert
openssl req -new -nodes -out "$SRV_DIR/$MYCERT.csr" -newkey rsa:4096 -keyout "$SRV_DIR/$MYCERT.key" -quiet -subj '/CN=DiplomskiSRV/C=RS/ST=Serbia/L=Serbia/O=ETF' 


echo "Generating Server v3 ext..."
# create a v3 ext file for SAN properties
cat > "$SRV_DIR/$MYCERT.v3.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = $SRV_HOSTNAME 
IP.1 = $SRV_IP 
EOF

echo "Signing Server certificate with CA certificate..."
openssl x509 -req -in "$SRV_DIR/$MYCERT.csr" -CA "$CA_DIR/$CANAME.crt" -CAkey "$CA_DIR/$CANAME.key" -CAcreateserial -out "$SRV_DIR/$MYCERT.crt" -days 730 -sha256 -extfile "$SRV_DIR/$MYCERT.v3.ext" --passin pass:$PASSPHRASE
