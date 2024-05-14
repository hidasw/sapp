cls
@echo off
php ../pdfsign.php ../examples/testdoc.pdf "cert/longChain.pfx" > pdfsign.pdf
pause
sign.bat