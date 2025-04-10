<?php
echo "<pre>";
use ddn\sapp\PDFDoc;

require_once('../vendor/autoload.php');
$file_in = 'pdf.pdf';
$file_content = file_get_contents($file_in);
$pfx = "cert/66.pem.pfx";

echo "PAdES-bb\n\n";
echo "Signing , file \"$file_in\" ...\n\n";
$obj = PDFDoc::from_string($file_content);
if($obj === false) {
  echo "failed to parse file $file_in\n";
} else {
  $obj->set_ltv(); // ocsp host, crl addr, issuer
  $obj->set_tsa('http://localhost/ca/tsa/');
  $password = '';
  if(!$obj->set_signature_certificate($pfx, $password)) {
    echo "the certificate is not valid\n";
  } else {
    define('__SIGNATURE_MAX_LENGTH', 29000);
    $docsigned = $obj->to_pdf_file_s();
    if($docsigned === false) {
      echo "could not sign the document\n";
    } else {
      $file_out = 'sapp_ecc_pades_b-b.pdf';
      echo "OK. file \"$file_in\" signed to \"$file_out\"\n";
      $h = fopen($file_out,'w');
      fwrite($h, $docsigned);
      fclose($h);
    }
  }
}

echo "PAdES-bl\n\n";
echo "Signing ...\n\n";
$obj = PDFDoc::from_string($docsigned);
if($obj === false) {
  echo "failed to parse file $file_in\n";
} else {
  $obj->set_ltv(); // ocsp host, crl addr, issuer
  $obj->set_tsa('http://localhost/ca/tsa/');
  $password = '';
  if(!$obj->set_signature_certificate($pfx, $password)) {
    echo "the certificate is not valid\n";
  } else {
    $docsigned = $obj->to_pdf_file_lt();
    if($docsigned === false) {
      echo "could not sign the document\n";
    } else {
      $file_out = 'sapp_ecc_pades_b-l.pdf';
      echo "OK. file \"$file_in\" signed to \"$file_out\"\n";
      $h = fopen($file_out,'w');
      fwrite($h, $docsigned);
      fclose($h);
    }
  }
}
echo "PAdES-blta\n\n";
echo "Signing ...\n\n";
$obj = PDFDoc::from_string($docsigned);
if($obj === false) {
  echo "failed to parse file $file_in\n";
} else {
  $obj->set_ltv(); // ocsp host, crl addr, issuer
  $obj->set_tsa('http://localhost/ca/tsa/');
  $password = '';
  if(!$obj->set_signature_certificate($pfx, $password)) {
    echo "the certificate is not valid\n";
  } else {
    $docsigned = $obj->to_pdf_file_ts();
    if($docsigned === false) {
      echo "could not sign the document\n";
    } else {
      $file_out = 'sapp_ecc_pades_b-lta.pdf';
      echo "OK. file \"$file_in\" signed to \"$file_out\"\n";
      $h = fopen($file_out,'w');
      fwrite($h, $docsigned);
      fclose($h);
    }
  }
}

?>