#!/usr/bin/env php
<?php
/*
    This file is part of SAPP

    Simple and Agnostic PDF Parser (SAPP) - Parse PDF documents in PHP (and update them)
    Copyright (C) 2020 - Carlos de Alfonso (caralla76@gmail.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

use ddn\sapp\PDFDoc;

require_once('vendor/autoload.php');

if ($argc < 4) {
    fwrite(STDERR, sprintf("usage: %s <filename> <image> <certfile> <tsaUrl> <LTVenabled=true> <LtvOcsp> <LtvCrl> <LtvIssuer>\n
filename         - pdf document to sign.
image            - image to displayed in signature appearance.
certfile         - pkcs12 certificate file to sign pdf.
tsaUrl           - optional TSA server url to timestamp pdf document. set \"notsa\" to skip for add next argument.
LTVenabled       - optional set \"true\" to enable LTV.
LtvOcsp          - optional custom OCSP Url to validate cert file.\n                            set \"noocsp\" to disable, set \"ocspaia\" to lookup in certificate attributes.
crlUrlorFile     - optional custom Crl filename/url to validate cert.\n                            set \"crlcdp\" to use default crl cdp address lookup in certificate attributes.
IssuerUrlorFile  - optional custom issuer filename/url.\n                            will lookup in certificate attributes if not set.\n
", $argv[0]));
} else {
    if (!file_exists($argv[1])) {
        fwrite(STDERR, "failed to open file " . $argv[1]);
    } else {
        // Silently prompt for the password
        fwrite(STDERR, "Password: ");
        system('stty -echo');
        $password = trim(fgets(STDIN));
        system('stty echo');
        fwrite(STDERR, "\n");

        $file_content = file_get_contents($argv[1]);
        $obj = PDFDoc::from_string($file_content);
        
        if ($obj === false) {
            fwrite(STDERR, "failed to parse file " . $argv[1]);
        } else {
                if ($argc > 4) {
                    $obj->set_tsa($argv[4]);
                }
                if ($argc > 5) {
                    if ($argv[5] === 'true') {
                        $ocspUrl = null;
                        $crl = null;
                        if ($argc > 6) {
                          if ($argv[6] === 'noocsp') {
                              $ocspUrl = false;
                          } elseif ($argv[6] === 'ocspaia') {
                              $ocspUrl = null;
                          } else {
                              $ocspUrl = $argv[6];
                          }
                        }
                        if ($argc > 7) {
                          if ($argv[7] === 'crlcdp') {
                              $crl = null;
                          } else {
                              $crl = $argv[7];
                          }
                        }
                        
                        $issuer = false;
                        if ($argc > 8) {
                            $issuer = $argv[8];
                        }
                        $obj->set_ltv($ocspUrl, $crl ,$issuer);
                    }
                }
            $signedDoc = $obj->sign_document($argv[3], $password, 0, $argv[2]);
            if ($signedDoc === false) {
                fwrite(STDERR, "failed to sign the document");
            } else {
                $docsigned = $signedDoc->to_pdf_file_s();
                if ($docsigned === false) {
                    fwrite(STDERR, "could not sign the document");
                } else {
                    echo $docsigned;
                }
            }
        }
    }
}
?>
