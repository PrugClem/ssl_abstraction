
# generate root certificate key
echo -e "[LOG] generating root rsa key"
openssl genrsa -out root.key 2048

# generate root certificate for 20'000 days
echo -e "[LOG] generating root certificate"
openssl req -x509 -new -nodes -key root.key -days 20000 -out root.crt -subj "/C=AT/ST=LA/L=VIE/O=Private/OU=Private/CN=root certificate"
