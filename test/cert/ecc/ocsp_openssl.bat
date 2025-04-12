openssl ocsp -text -url http://localhost:8888 -issuer "ecica2.pem" -CApath "G:\Engines\CertificateAuthority" -cert "ecc.cer" -respout ec_resp.der -reqout ec_req.der
pause
ocsp_openssl.bat