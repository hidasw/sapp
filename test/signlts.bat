cls
@echo off
php ../pdfsignlts.php ../examples/testdoc.pdf "cert/longChain.pfx" https://hida.local/tsa > signlts.pdf
pause
signlts.bat