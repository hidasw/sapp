cls
@echo off
rem php ../pdfsignlts.php pdf.pdf "cert/ecc/ecc Test.pfx" "http://timestamp.apple.com/ts01" > pdf_signed.pdf
rem php ../pdfsignlts.php pdf.pdf "cert/ecc/ecc Test.pfx" "https://bteszt.e-szigno.hu/tsa" > sapp_newsigned.pdf
rem php ../pdfsignlts.php pdf.pdf "cert/ecc/60.pem.pfx" "https://bteszt.e-szigno.hu/tsa" > sapp_newsigned.pdf
rem php ../pdfsignlts.php pdf.pdf "cert/ecc/60.pem.pfx" "http://localhost/tsa" > sapp_newsigned.pdf
rem php ../pdfsignlts.php pdf.pdf "cert/ecc/66.pem.pfx" "http://ts.hdx.my.id/" > sapp_newsigned.pdf
php ../pdfsignlts.php pdf.pdf "cert/ecc/66.pem.pfx" "http://debian/ca/tsa/" > sapp_newsigned.pdf
rem php ../pdfsignlts.php pdf.pdf "cert/ecc/ecc Test.pfx" "http://localhost/tsa/" > sapp_signed_tsa-localhost.pdf
rem php ../pdfsignlts.php pdf.pdf "cert/long.pfx" "http://localhost/tsa/" > result.pdf

pause
sign.bat