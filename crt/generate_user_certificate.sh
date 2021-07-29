
echo -e "[LOG] generating server rsa key"
openssl genrsa -out server.key 2048

echo -e "[LOG] create server certificate signing request"
openssl req -new -key server.key -out server.csr -subj "/C=AT/ST=LA/L=VIE/O=Private/OU=Private/CN=server certificate"

echo -e "[LOG] sign the server certificate using the root certificate"
openssl x509 -req -in server.csr -CA root.crt -CAkey root.key -CAcreateserial -out server.crt -days 20000


echo -e "[LOG] generating client rsa key"
openssl genrsa -out client.key 2048

echo -e "[LOG] create client certificate signing request"
openssl req -new -key client.key -out client.csr -subj "/C=AT/ST=LA/L=VIE/O=Private/OU=Private/CN=client certificate"

echo -e "[LOG] sign the client certificate using the root certificate"
openssl x509 -req -in client.csr -CA root.crt -CAkey root.key -CAcreateserial -out client.crt -days 20000


# generate diffie-Hellman parameters for key exchange
echo -e "[LOG] generating DH parameter file"
openssl dhparam -out dh4096.pem 4096
