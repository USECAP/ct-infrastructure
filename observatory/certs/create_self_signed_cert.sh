#/bin/bash

# generate ca key and chain file
echo "generate ca key and chain file"
openssl req -new -x509 -extensions v3_ca -keyout ca.key -out observatory_chain.pem -days 365

# generate key files
#openssl req -x509 -newkey rsa:4096 -keyout observatory_key.pem -out observatory.pem -days 365
echo  "generate key files"
openssl genrsa -out observatory_key.pem 4096

# generate csr
echo "generate csr"
openssl req -new -key observatory_key.pem -out certificate.csr

# sign it
echo "sign it"
openssl x509 -req -days 365 -in certificate.csr -CA observatory_chain.pem -CAkey ca.key -set_serial 01 -out observatory.pem

#remove csr
echo "remove csr"
rm certificate.csr
