<?php
echo "<pre>";
use ddn\sapp\PDFDoc;

require_once('../vendor/autoload.php');
$file_in = 'pdf.pdf';
$file_content = file_get_contents($file_in);
//$pfx = "cert/ecc/66.pem.pfx";
$pfx = "cert/66.pem.pfx";

echo "Signing file \"$file_in\" ...\n\n";
$obj = PDFDoc::from_string($file_content);
if($obj === false) {
  echo "failed to parse file $file_in\n";
} else {
  $obj->set_ltv(); // ocsp host, crl addr, issuer
  //$obj->set_ltv(false, $crl, $issuer); // ocsp host, crl addr, issuer
  //$obj->set_tsa('http://timestamp.apple.com/ts01');
  //$obj->set_tsa('http://debian/ca/tsa/');
  $obj->set_tsa('http://localhost/ca/tsa/');
  //$obj->set_tsa('https://bteszt.e-szigno.hu/tsa','teszt','teszt');
  $password = '';
  //$pfx = file_get_contents($pfx);
  if(!$obj->set_signature_certificate($pfx, $password)) {
    echo "the certificate is not valid\n";
  } else {
    define('__SIGNATURE_MAX_LENGTH', 29000);
    $docsigned = $obj->to_pdf_file_s();
    if($docsigned === false) {
      echo "could not sign the document\n";
    } else {
      //$file_out = './test/signed_'.($filenum+1).'.pdf';
      $file_out = 'sapp_ecc_pades_b-b.pdf';
      echo "OK. file \"$file_in\" signed to \"$file_out\"\n";
      $h = fopen($file_out,'w');
      fwrite($h, $docsigned);
      fclose($h);
    }
  }
}

echo "Signing file2 \"$file_in\" ...\n\n";
$obj = PDFDoc::from_string($docsigned);
if($obj === false) {
  echo "failed to parse file $file_in\n";
} else {
  $obj->set_ltv(); // ocsp host, crl addr, issuer
  //$obj->set_ltv(false, $crl, $issuer); // ocsp host, crl addr, issuer
  //$obj->set_tsa('http://timestamp.apple.com/ts01');
  //$obj->set_tsa('http://debian/ca/tsa/');
  $obj->set_tsa('http://localhost/ca/tsa/');
  //$obj->set_tsa('https://bteszt.e-szigno.hu/tsa','teszt','teszt');
  $password = '';
  //$pfx = file_get_contents($pfx);
  if(!$obj->set_signature_certificate($pfx, $password)) {
    echo "the certificate is not valid\n";
  } else {
    //define('__SIGNATURE_MAX_LENGTH', 20000);
    $docsigned = $obj->to_pdf_file_lt();
    if($docsigned === false) {
      echo "could not sign the document\n";
    } else {
      //$file_out = './test/signed_'.($filenum+1).'.pdf';
      $file_out = 'sapp_ecc_pades_b-l.pdf';
      echo "OK. file \"$file_in\" signed to \"$file_out\"\n";
      $h = fopen($file_out,'w');
      fwrite($h, $docsigned);
      fclose($h);
    }
  }
}
echo "tsSigning file2 \"$file_in\" ...\n\n";
$obj = PDFDoc::from_string($docsigned);
if($obj === false) {
  echo "failed to parse file $file_in\n";
} else {
  $obj->set_ltv(); // ocsp host, crl addr, issuer
  //$obj->set_ltv(false, $crl, $issuer); // ocsp host, crl addr, issuer
  //$obj->set_tsa('http://timestamp.apple.com/ts01');
  //$obj->set_tsa('http://debian/ca/tsa/');
  $obj->set_tsa('http://localhost/ca/tsa/');
  //$obj->set_tsa('https://bteszt.e-szigno.hu/tsa','teszt','teszt');
  $password = '';
  //$pfx = file_get_contents($pfx);
  if(!$obj->set_signature_certificate($pfx, $password)) {
    echo "the certificate is not valid\n";
  } else {
    //define('__SIGNATURE_MAX_LENGTH', 20000);
    $docsigned = $obj->to_pdf_file_ts();
    if($docsigned === false) {
      echo "could not sign the document\n";
    } else {
      //$file_out = './test/signed_'.($filenum+1).'.pdf';
      $file_out = 'sapp_ecc_pades_b-lta.pdf';
      echo "OK. file \"$file_in\" signed to \"$file_out\"\n";
      $h = fopen($file_out,'w');
      fwrite($h, $docsigned);
      fclose($h);
    }
  }
}

?>