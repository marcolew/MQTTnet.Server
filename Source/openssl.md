# Root
openssl genrsa -out root.key 2048
openssl genrsa -des3 -out root.key 2048
openssl req -new -key root.key -out root.csr
openssl x509 -req -days 1095 -sha1 -extensions v3_ca -signkey root.key -in root.csr -out root.crt
openssl pkcs12 -export -out root.pfx -inkey root.key -in root.crt

# MQTT Server
openssl genrsa -out mqtt-server.key 2048
openssl req -new -key mqtt-server.key -out mqtt-server.csr
openssl x509 -req -days 1095 -sha1 -extensions v3_req -CA root.crt -CAkey root.key -CAcreateserial -in mqtt-server.csr -out mqtt-server.crt
openssl pkcs12 -export -out mqtt-server.pfx -inkey mqtt-server.key -in mqtt-server.crt

# MQTT Client
openssl genrsa -out mqtt-client1.key 2048
openssl req -new -key mqtt-client1.key -out mqtt-client1.csr
openssl x509 -req -days 1095 -sha1 -extensions v3_req -CA root.crt -CAkey root.key -CAcreateserial -in mqtt-client1.csr -out mqtt-client1.crt
openssl pkcs12 -export -out mqtt-client1.pfx -inkey mqtt-client1.key -in mqtt-client1.crt