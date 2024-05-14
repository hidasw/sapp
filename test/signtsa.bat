cls
@echo off
php ../pdfsigntsa.php ../examples/testdoc.pdf "cert/longChain.pfx" > signtsa.pdf
pause
signtsa.bat