rem openssl ocsp -text -url http://localhost/ocsp/ -issuer "Intermediate CA Test.pem" -CApath "." -cert "User Test 1024Bit.pem" 
openssl ocsp -text -url http://localhost/ocsp/ -issuer "PDF Signing CA.pem" -CApath "." -nonce -signer "long.pem" -policy 1.2.3 -cert "long.pem" 
rem openssl ocsp -text -url http://localhost/ocsp/ -issuer "Intermediate CA Test.pem" -CApath "." -nonce -signer "User Test 1024Bit.pem" -policy 1.2.3 -serial 1 -serial 2 -cert "User Test 1024Bit.pem" 
pause
ocspclient.bat