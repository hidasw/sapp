rem openssl ocsp -text -url http://localhost/ocsp/ -issuer "ec Root CA test.pem" -CApath "." -cert "65.pem" 
openssl ocsp -text -url http://ocsp.hdx.my.id/ -issuer "ec Root CA test.pem" -CApath "." -cert "60.pem" 
pause
ocsp.bat