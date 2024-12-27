Izumi

==

TLSTCP Protocol implemented to extend TCP. 
- available through pkg/tsltcp
- TCP connections work
- TLS Handshake Fails

Testing Instructions

```bash
#Server
apk add openssl
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 1 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
openssl s_server -accept 8000 -cert cert.pem -key key.pem

#Client
apk add openssl
openssl s_client -connect 192.168.0.4:8000


```
