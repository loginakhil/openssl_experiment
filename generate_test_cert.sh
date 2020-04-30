#!/bin/bash

openssl req \
    -x509 -newkey rsa:4096 \
    -keyout key.pem \
    -out cert.pem \
    -passout pass:testpassword \
    -days 365 \
    -subj "/C=US/ST=Oregon/L=Portland/O=Company Name/OU=Org/CN=www.example.com"

