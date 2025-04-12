rem openssl ocsp -text -url http://localhost/ocsp/ -issuer "ec Root CA test.pem" -CApath "." -cert "65.pem" 
openssl ocsp -text -url http://localhost/ca/ocsp/ -issuer "Hda Root Authority G2.crt" -CApath "." -cert "Intermediate TSA G3.pem" 
pause
ocspicatsa.bat