rem openssl ocsp -text -url http://localhost/ocsp/ -issuer "ec Root CA test.pem" -CApath "." -cert "65.pem" 
openssl ocsp -text -url http://localhost/ca/ocsp/ -issuer "Intermediate TSA G3.pem" -CApath "." -cert "tsa.pem" 
pause
ocsptsa.bat