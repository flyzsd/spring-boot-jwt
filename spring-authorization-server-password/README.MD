# spring-authorization-server-password

It is a Spring Boot application, that contains all necessary configurations to be able to try oauth2 authorization (password flow).
It uses JWT token key for the authorization.

## How to test
Please refer to test.http

## Use Asymmetric KeyPair to sign JWT token
1: Generate JKS Java KeyStore File
keytool -genkeypair -alias mytest -keyalg RSA -keypass mypass -keystore mytest.jks -storepass mypass

2: Export Public Key
keytool -list -rfc --keystore mytest.jks | openssl x509 -inform pem -pubkey
