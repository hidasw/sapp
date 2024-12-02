<?php
namespace ddn\sapp\helpers;
/*
// File name   : CMS.php
// Version     : 1.2
// Last Update : 2024-09-07
// Author      : Hida - https://github.com/hidasw
// License     : GNU GPLv3
*/
/**
 * @class cms
 * Manage CMS(Cryptographic Message Syntax) Signature for SAPP PDF
 */
 
 define('TSA_REQUIRED', 1); // set true to abort if tsa fail

class CMS {
    public $signature_data;

  /**
   * send tsa/ocsp query with curl
   * @param array $reqData
   * @return string response body
   * @public
   */
  public function sendReq($reqData) {
    if (!function_exists('curl_init')) {
      p_error('         Please enable cURL PHP extension!');
    }
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $reqData['uri']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_HEADER, 1);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array("Content-Type: {$reqData['req_contentType']}",'User-Agent: SAPP PDF'));
    curl_setopt($ch, CURLOPT_POSTFIELDS, $reqData['data']);
    if (($reqData['user'] ?? null) && ($reqData['password'] ?? null)) {
        curl_setopt($ch, CURLOPT_USERPWD, $reqData['user'] . ':' . $reqData['password']);
    }
    $tsResponse = curl_exec($ch);

    if($tsResponse) {
      $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
      curl_close($ch);
      $header = substr($tsResponse, 0, $header_size);
      $body = substr($tsResponse, $header_size);
      // Get the HTTP response code
      $headers = explode("\n", $header);
      foreach ($headers as $key => $r) {
        if (stripos($r, 'HTTP/') === 0) {
          list(,$code, $status) = explode(' ', $r, 3);
          break;
        }
      }
      if($code != '200') {
        p_error("      response error! Code=\"$code\", Status=\"".trim($status??"")."\"");
        return false;
      }
      $contentTypeHeader = '';
      $headers = explode("\n", $header);
      foreach ($headers as $key => $r) {
        // Match the header name up to ':', compare lower case
        if (stripos($r, "Content-Type".':') === 0) {
          list($headername, $headervalue) = explode(":", $r, 2);
          $contentTypeHeader = trim($headervalue);
        }
      }
      if($contentTypeHeader != $reqData['resp_contentType']) {
        p_error("      response content type not {$reqData['resp_contentType']}, but: \"$contentTypeHeader\"");
        return false;
      }
      if(empty($body)) {
        p_error('         error empty response!');
      }
      return $body; // binary response
    }
  }

  /**
   * get issuer certificate via curl
   * @param string $url url of issuer AIA address
   * @param string &$err return false on success or error message string on error
   * @return issuer certificate or false on error
   */
  protected function urlFetch($url, &$err=false) {
    $url = str_replace(' ', '%20', $url);
    if(ini_get('allow_url_fopen') ) {
      if($response = file_get_contents($url)) {
        return $response;
      }
    }
    if (!function_exists('curl_init')) {
      $err = "allow_url_fopen not enabled and cURL not enabled!, please enable one of them.\n";
      return false;
    }
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, 2000);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5000);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, false);
    $response = curl_exec($ch);
    $info =curl_getinfo($ch);
    if(!$response) {
      $err = curl_errno($ch).curl_error($ch);
      return false;
    }
    if($info['http_code'] != 200) {
      $err = $info['http_code'];
      return false;
    }
    return $response; // binary response
  }

  /**
   * parse tsa response to array
   * @param string $binaryTsaRespData binary tsa response to parse
   * @return array asn.1 hex structure of tsa response
   */
  private function tsa_parseResp($binaryTsaRespData) {
    if(!@$ar = asn1::parse(bin2hex($binaryTsaRespData), 3)) {
      p_error("      can't parse invalid tsa Response.");
      return false;
    }
    $curr = $ar;
    foreach($curr as $key=>$value) {
      if($value['type'] == '30') {
        $curr['TimeStampResp']=$curr[$key];
        unset($curr[$key]);
      }
    }
    $ar=$curr;
    $curr = $ar['TimeStampResp'];
    foreach($curr as $key=>$value) {
      if(is_numeric($key)) {
        if($value['type'] == '30' && !array_key_exists('status', $curr)) {
          $curr['status']=$curr[$key];
          unset($curr[$key]);
        } else if($value['type'] == '30') {
          $curr['timeStampToken']=$curr[$key];
          unset($curr[$key]);
        }
      }
    }
    $ar['TimeStampResp']=$curr;
    $curr = $ar['TimeStampResp']['timeStampToken'];
    foreach($curr as $key=>$value) {
      if(is_numeric($key)) {
        if($value['type'] == '06') {
          $curr['contentType']=$curr[$key];
          unset($curr[$key]);
        }
        if($value['type'] == 'a0') {
          $curr['content']=$curr[$key];
          unset($curr[$key]);
        }
      }
    }
    $ar['TimeStampResp']['timeStampToken'] = $curr;
    $curr = $ar['TimeStampResp']['timeStampToken']['content'];
    foreach($curr as $key=>$value) {
      if(is_numeric($key)) {
        if($value['type'] == '30') {
          $curr['TSTInfo']=$curr[$key];
          unset($curr[$key]);
        }
      }
    }
    $ar['TimeStampResp']['timeStampToken']['content'] = $curr;
    if(@$ar['TimeStampResp']['timeStampToken']['content']['hexdump'] != '') {
      return $ar;
    } else {
       return false;
    }
  }

  /**
   * Create timestamp query
   * @param string $data binary data to hashed/digested
   * @param string $hashAlg hash algorithm
   * @return string hex TSTinfo.
   */
  protected function createTimestamp($data, $hashAlg='sha1') {
    $TSTInfo=false;
    $tsaQuery = x509::tsa_query($data, $hashAlg);
    $tsaData = $this->signature_data['tsa'];
    $reqData = array(
        'data'=>$tsaQuery,
        'uri'=>$tsaData['host'],
        'req_contentType'=>'application/timestamp-query',
        'resp_contentType'=>'application/timestamp-reply'
    ) + $tsaData;

    p_debug("    sending TSA query to \"".$tsaData['host']."\"...");
    if(!$binaryTsaResp = self::sendReq($reqData)) {
      p_error("      TSA query send FAILED!");
    } else {
      p_debug("      TSA query send OK.");
      p_debug("    Parsing Timestamp response...");
      if(!$tsaResp = $this->tsa_parseResp($binaryTsaResp)) {
        p_error("      parsing FAILED!");
      }
      p_debug("      parsing OK.");
      $TSTInfo = $tsaResp['TimeStampResp']['timeStampToken']['hexdump'];
    }
    return $TSTInfo;
  }

  /**
   * Perform OCSP/CRL Validation
   * @param array $parsedCert parsed certificate
   * @param string $ocspURI
   * @param string $crlURIorFILE
   * @param string $issuerURIorFILE
   * @return array
   */
  protected function LTVvalidation($parsedCert, $ocspURI=null, $crlURIorFILE=null, $issuerURIorFILE=false, $certTocheck = false) {
    $oid2hash['1.2.840.10045.4.1'] = 'sha1';
    $oid2hash['1.2.840.10045.4.3.1'] = 'sha224';
    $oid2hash['1.2.840.10045.4.3.2'] = 'sha256';
    $oid2hash['1.2.840.10045.4.3.3'] = 'sha384';
    $oid2hash['1.2.840.10045.4.3.4'] = 'sha512';
    $oid2hash['1.2.840.113549.1.1.5'] = 'sha1';
    $oid2hash['1.2.840.113549.1.1.14'] = 'sha224';
    $oid2hash['1.2.840.113549.1.1.11'] = 'sha256';
    $oid2hash['1.2.840.113549.1.1.12'] = 'sha384';
    $oid2hash['1.2.840.113549.1.1.13'] = 'sha512';
    
    $ltvResult['issuer']=false;
    $ltvResult['ocsp']=false;
    $ltvResult['crl']=false;
    $certSigner_parse = $parsedCert;
    p_debug("    getting OCSP & CRL address...");
    p_debug("      reading AIA OCSP attribute...");
    $ocspURI = @$certSigner_parse['tbsCertificate']['attributes']['1.3.6.1.5.5.7.1.1']['value']['1.3.6.1.5.5.7.48.1'][0];
    if(empty(trim($ocspURI))) {
      p_warning("        FAILED!");
    } else {
      p_debug("        OK. got address:\"$ocspURI\"");
    }
    $ocspURI = trim($ocspURI);
    p_debug("      reading CRL CDP attribute...");
    $crlURIorFILE = @$certSigner_parse['tbsCertificate']['attributes']['2.5.29.31']['value'][0];
    if(empty(trim($crlURIorFILE??""))) {
      p_warning("        FAILED!");
    } else {
      p_debug("        OK. got address:\"$crlURIorFILE\"");
    }
    if(empty($ocspURI) && empty($crlURIorFILE)) {
      p_error("    can't get OCSP/CRL address! Process terminated.");
    } else { // Perform if either ocspURI/crlURIorFILE exists
      p_debug("    getting Issuer...");
      p_debug("      looking for issuer address from AIA attribute...");
      $issuerURIorFILE = @$certSigner_parse['tbsCertificate']['attributes']['1.3.6.1.5.5.7.1.1']['value']['1.3.6.1.5.5.7.48.2'][0];
      $issuerURIorFILE = trim($issuerURIorFILE??"");
      if(empty($issuerURIorFILE)) {
        p_debug("        FAILED!");
      } else {
        p_debug("        OK. got address \"$issuerURIorFILE\"...");
        p_debug("      load issuer from \"$issuerURIorFILE\"...");
        if($issuerCert = self::urlFetch($issuerURIorFILE, $err)) {
          p_debug("        OK. size ".round(strlen($issuerCert)/1024,2)."Kb");
          p_debug("      reading issuer certificate...");
          if($issuer_certDER = x509::get_cert($issuerCert)) {
            p_debug("        OK.");
            p_debug("      check if issuer is cert issuer...");
            if(!$chain_public_key = openssl_pkey_get_public(x509::x509_der2pem($issuer_certDER))) {
              p_error("        getting pubKey... FAILED!");
            } else {
              p_debug("        getting pubKey... OK.");
              $r = openssl_x509_verify(x509::x509_der2pem(x509::get_cert($certTocheck)), $chain_public_key);
              if($r == 1) {
                p_debug("        verifying signature... OK.");
                p_debug("        result: This CA is the Issuer.");
                $ltvResult['issuer'] = $issuer_certDER;
              } else {
                p_warning("        verifying signature... FAILED!.");
                p_warning("        result: This CA is NOT the Issuer");
              }
            }
            $certIssuer_parse = x509::readcert($issuer_certDER, 'oid'); // Parsing Issuer cert
          } else {
            p_warning("        FAILED!");
          }
        } else {
          p_warning("        FAILED!. error:$err");
        }
      }
      
      if(!$ltvResult['issuer']) {
        p_debug("      search for issuer in extracerts.....");
        if(array_key_exists('extracerts', $this->signature_data) && ($this->signature_data['extracerts'] !== null) && (count($this->signature_data['extracerts']) > 0)) {
          $i=0;
          foreach($this->signature_data['extracerts'] as $extracert) {
            p_debug("        extracerts[$i] ...");
            if(!$chain_public_key = openssl_pkey_get_public($extracert)) {
              p_error("          getting pubKey... FAILED!");
            } else {
              p_debug("          getting pubKey... OK.");
              $r = openssl_x509_verify(x509::x509_der2pem(x509::get_cert($certTocheck)), $chain_public_key);
              if($r == 1) {
                p_debug("          verifying signature... OK.");
                p_debug("          result: This CA is the Issuer.");
                $certIssuer_parse = x509::readcert($extracert, 'oid'); // Parsing Issuer cert
                $ltvResult['issuer'] = x509::get_cert($extracert);
              } else {
                p_warning("          verifying signature... FAILED!.");
                p_warning("          result: This CA is NOT the Issuer");
              }
            }
            $i++;
          }
        } else {
          p_error("        FAILED! no extracerts available");
        }
      }
      
    }
    
    if($ltvResult['issuer']) {
      if(!empty($ocspURI)) {
        p_debug("    OCSP start...");
        $ocspReq_serialNumber = $certSigner_parse['tbsCertificate']['serialNumber'];
        $ocspReq_issuerNameHash = $certIssuer_parse['tbsCertificate']['subject']['sha1'];
        $ocspReq_issuerKeyHash = $certIssuer_parse['tbsCertificate']['subjectPublicKeyInfo']['sha1'];
        $ocspRequestorSubjName = $certSigner_parse['tbsCertificate']['subject']['hexdump'];
        p_debug("      OCSP create request...");
        if($ocspReq = x509::ocsp_request($ocspReq_serialNumber, $ocspReq_issuerNameHash, $ocspReq_issuerKeyHash)) {
          p_debug("        OK.");
          $ocspBinReq = pack("H*", $ocspReq);
          $reqData = array(
                          'data'=>$ocspBinReq,
                          'uri'=>$ocspURI,
                          'req_contentType'=>'application/ocsp-request',
                          'resp_contentType'=>'application/ocsp-response'
                          );
          p_debug("      OCSP send request to \"$ocspURI\"...");
          if($ocspResp = self::sendReq($reqData)) {
            p_debug("        OK.");
            p_debug("      OCSP parsing response...");
            if($ocsp_parse = x509::ocsp_response_parse($ocspResp, $return)) {
              p_debug("        OK.");
              p_debug("      OCSP check cert validity...");
              $certStatus = $ocsp_parse['responseBytes']['response']['BasicOCSPResponse']['tbsResponseData']['responses'][0]['certStatus'];
              if($certStatus == 'valid') {
                p_debug("        OK. VALID.");
                $ocspRespHex = $ocsp_parse['hexdump'];
                $ltvResult['ocsp'] = $ocspRespHex;
              } else {
                p_warning("        FAILED! cert not valid, status:\"".strtoupper($certStatus)."\"");
              }
            } else {
              p_warning("        FAILED! Ocsp server status \"$return\"");
            }
          } else {
            p_warning("        FAILED!");
          }
        } else {
          p_warning("      FAILED!");
        }
      }
      
      if(!$ltvResult['ocsp']) { // CRL not processed if OCSP validation already success
        if(!empty($crlURIorFILE)) {
          p_debug("    processing CRL validation since OCSP not done/failed...");
          p_debug("      getting crl from \"$crlURIorFILE\"...");
          if($crl = self::urlFetch($crlURIorFILE, $err)) {
            p_debug("        OK. size ".round(strlen($crl)/1024,2)."Kb");
            p_debug("      reading crl...");
            if($crlread=x509::crl_read($crl)) {
              p_debug("        OK.");
              p_debug("      verify crl signature...");
              $crl_signatureField = $crlread['parse']['signature'];
              $hashAlgo = constant('OPENSSL_ALGO_'.strtoupper($oid2hash[$crlread['parse']['signatureAlgorithm']]));
              if(openssl_verify(hex2bin($crlread['parse']['TBSCertList']['hexdump']), hex2bin($crl_signatureField), x509::x509_der2pem($ltvResult['issuer']), $hashAlgo)) {
                p_debug("        OK.");
                p_debug("      check CRL validity...");
                $crl_parse=$crlread['parse'];
                $thisUpdate = str_pad($crl_parse['TBSCertList']['thisUpdate'], 15, "20", STR_PAD_LEFT);
                $thisUpdateTime = strtotime($thisUpdate);
                $nextUpdate = str_pad($crl_parse['TBSCertList']['nextUpdate'], 15, "20", STR_PAD_LEFT);
                $nextUpdateTime = strtotime($nextUpdate);
                $nowz = strtotime("now");
                if(($nowz-$thisUpdateTime) < 0) { // 0 sec after valid
                  p_error("        FAILED! not yet valid! valid at ".date("d/m/Y H:i:s", $thisUpdateTime));
                } elseif(($nextUpdateTime-$nowz) < 1) { // not accept if crl 1 sec remain to expired
                  p_error("        FAILED! Expired crl at ".date("d/m/Y H:i:s", $nextUpdateTime)." and now ".date("d/m/Y H:i:s", $nowz)."!");
                } else {
                  p_debug("        OK. CRL still valid until ".date("d/m/Y H:i:s", $nextUpdateTime)."");
                  $crlCertValid=true;
                  p_debug("      check if cert not revoked...");
                  if(array_key_exists('revokedCertificates', $crl_parse['TBSCertList'])) {
                    $certSigner_serialNumber = $certSigner_parse['tbsCertificate']['serialNumber'];
                    if(array_key_exists($certSigner_serialNumber, $crl_parse['TBSCertList']['revokedCertificates']['lists'])) {
                      $crlCertValid=false;
                      p_error("        FAILED! Certificate Revoked!");
                    }
                  }
                  if($crlCertValid == true) {
                    p_debug("        OK. VALID");
                    $crlHex = current(unpack('H*', $crlread['der']));
                    $ltvResult['crl'] = $crlHex;
                  }
                }
              } else {
                p_error("        FAILED! Wrong CRL.");
              }
            } else {
              p_error("        FAILED! can't read crl");
            }
          } else {
            p_error("        FAILED! can't get crl. error:$err");
          }
        }
      }
    }
    if(!$ltvResult['issuer']) {
      return false;
    }
    if(!$ltvResult['ocsp'] && !$ltvResult['crl']) {
      return false;
    }
    return $ltvResult;
  }
  
  /**
   * Perform PKCS7 Signing
   * @param string $binaryData
   * @return string hex + padding 0
   * @public
   */
  public function pkcs7_sign($binaryData) {
    $hexOidHashAlgos = array(
        'md2'=>'06082A864886F70D0202',
        'md4'=>'06082A864886F70D0204',
        'md5'=>'06082A864886F70D0205',
        'sha1'=>'06052B0E03021A',
        'sha224'=>'0609608648016503040204',
        'sha256'=>'0609608648016503040201',
        'sha384'=>'0609608648016503040202',
        'sha512'=>'0609608648016503040203'
    );
    $hashAlgorithm = $this->signature_data['hashAlgorithm'];
    if(!array_key_exists($hashAlgorithm, $hexOidHashAlgos)) {
      p_error("not support hash algorithm!");
      return false;
    }
    p_debug("hash algorithm is \"$hashAlgorithm\"");
    $x509 = new x509;
    if(!$certParse = $x509->readcert($this->signature_data['signcert'])) {
      p_error("certificate error! check certificate");
      exit;
    }
    $hexEmbedCerts[] = bin2hex($x509->get_cert($this->signature_data['signcert']));
    $appendLTV = '';
    $ltvData = $this->signature_data['ltv'];
    if(!empty($ltvData)) {
      p_debug("  LTV Validation start...");
      $appendLTV = '';
      $LTVvalidation_ocsp = '';
      $LTVvalidation_crl = '';
      $LTVvalidation_issuer = '';
      $LTVvalidationEnd = false;
      
      $isRootCA = false;
      if($certParse['tbsCertificate']['issuer']['hexdump'] == $certParse['tbsCertificate']['subject']['hexdump']) { // check whether root ca
          p_debug("***** \"{$certParse['tbsCertificate']['subject']['2.5.4.3'][0]}\" is a ROOT CA. No validation performed ***");
          $isRootCA = true;
      }
      if($isRootCA == false) {
        $i = 0;
        $LTVvalidation = true;
        $certtoCheck = $certParse;
        $certtoCheck_pem = $this->signature_data['signcert'];
        while($LTVvalidation !== false) {
          p_debug("========= $i checking \"{$certtoCheck['tbsCertificate']['subject']['2.5.4.3'][0]}\"===============");
          $LTVvalidation = self::LTVvalidation($certtoCheck, NULL, NULL, false, $certtoCheck_pem);
          $i++;
          if($LTVvalidation) {
            $curr_issuer = $LTVvalidation['issuer'];
            $certtoCheck = $x509->readcert($curr_issuer, 'oid');
            if(@$LTVvalidation['ocsp'] || @$LTVvalidation['crl']) {
              $LTVvalidation_ocsp .= $LTVvalidation['ocsp'];
              $LTVvalidation_crl .= $LTVvalidation['crl'];
              $hexEmbedCerts[] = bin2hex($LTVvalidation['issuer']);
              $certtoCheck_pem = $LTVvalidation['issuer'];
            }
            if($certtoCheck['tbsCertificate']['issuer']['hexdump'] == $certtoCheck['tbsCertificate']['subject']['hexdump']) { // check whether root ca
                p_debug("========= FINISH Reached ROOT CA \"{$certtoCheck['tbsCertificate']['subject']['2.5.4.3'][0]}\"===============");
                $LTVvalidationEnd = true;
                break;
            }
          }
        }
        
        if($LTVvalidationEnd) {
          p_debug("  LTV Validation SUCCESS\n");
          $ocsp = '';
          if(!empty($LTVvalidation_ocsp)) {
            $ocsp = asn1::expl(1,
                          asn1::seq(
                              $LTVvalidation_ocsp
                          )
                    );
          }
          $crl = '';
          if(!empty($LTVvalidation_crl)) {
            $crl = asn1::expl(0,
                      asn1::seq(
                        $LTVvalidation_crl
                      )
                    );
          }
          $appendLTV = asn1::seq(
                          "06092A864886F72F010108". // adbe-revocationInfoArchival (1.2.840.113583.1.1.8)
                          asn1::set(
                            asn1::seq(
                              $ocsp.
                              $crl
                            )
                          )
                        );
        } else {
          p_warning("  LTV Validation FAILED!\n");
        }
      }
      foreach($this->signature_data['extracerts'] ?? [] as $extracert) {
        $hex_extracert = bin2hex($x509->x509_pem2der($extracert));
        if(!in_array($hex_extracert, $hexEmbedCerts)) {
          $hexEmbedCerts[] = $hex_extracert;
        }
      }
    }
    $messageDigest = hash($hashAlgorithm, $binaryData);
    $authenticatedAttributes= asn1::seq(
            '06092A864886F70D010903'. //OBJ_pkcs9_contentType 1.2.840.113549.1.9.3
            asn1::set('06092A864886F70D010701')  //OBJ_pkcs7_data 1.2.840.113549.1.7.1
        ).
        asn1::seq( // signing time
            '06092A864886F70D010905'. //OBJ_pkcs9_signingTime 1.2.840.113549.1.9.5
            asn1::set(
                asn1::utime(date("ymdHis")) //UTTC Time
            )
        ).
        asn1::seq( // messageDigest
            '06092A864886F70D010904'. //OBJ_pkcs9_messageDigest 1.2.840.113549.1.9.4
            asn1::set(asn1::oct($messageDigest))
        ).$appendLTV;
    $tohash = asn1::set($authenticatedAttributes);
    $pkey = $this->signature_data['privkey'];
    if(!openssl_sign(hex2bin($tohash), $encryptedDigest, $pkey, constant('OPENSSL_ALGO_'.strtoupper($hashAlgorithm)))) {
      p_error("openssl_sign failed! process terminated.");
      return false;
    }
    $hexencryptedDigest = bin2hex($encryptedDigest);
    $timeStamp = '';
    if(!empty($this->signature_data['tsa'])) {
      p_debug("  Timestamping process start...");
      if(TSA_REQUIRED) {
        p_debug("  Timestamping is set to required.");
      } else {
        p_debug("  Timestamping is set to optional.");
      }
      if($TSTInfo = self::createTimestamp($encryptedDigest, $hashAlgorithm)) {
        p_debug("  Timestamping SUCCESS.");
        $TimeStampToken = asn1::seq(
            "060B2A864886F70D010910020E". // OBJ_id_smime_aa_timeStampToken 1.2.840.113549.1.9.16.2.14
            asn1::set($TSTInfo)
        );
        $timeStamp = asn1::expl(1,$TimeStampToken);
      } else {
        p_warning("  Timestamping FAILED!");
        if(TSA_REQUIRED) {
          p_error("  Timestamping is set to required! Process terminated!");
          return false;
        } else {
          p_debug("  Timestamping is not set to required! Ignored.");
        }
      }
    }
    $issuerName = $certParse['tbsCertificate']['issuer']['hexdump'];
    $serialNumber = $certParse['tbsCertificate']['serialNumber'];

    $resPkey = openssl_pkey_get_private($pkey);
    $pkeyDetails = openssl_pkey_get_details($resPkey);
    if($pkeyDetails['type'] == OPENSSL_KEYTYPE_RSA) {
      $signatureType = '06092A864886F70D010101'; // OBJ_rsaEncryption
      $signatureType .= '0500';
    }
    if($pkeyDetails['type'] == OPENSSL_KEYTYPE_EC) {
      $signatureType = '06072A8648CE3D0201'; // OBJ_X9_62_id_ecPublicKey
    }

    $signerinfos = asn1::seq(
        asn1::int('1').
        asn1::seq($issuerName . asn1::int($serialNumber)).
        asn1::seq($hexOidHashAlgos[$hashAlgorithm].'0500').
        asn1::expl(0, $authenticatedAttributes).
        asn1::seq($signatureType).
        asn1::oct($hexencryptedDigest).
        $timeStamp
    );
    $certs = asn1::expl(0, implode('', $hexEmbedCerts));
    $pkcs7contentSignedData = asn1::seq(
        asn1::int('1').
        asn1::set(asn1::seq($hexOidHashAlgos[$hashAlgorithm].'0500')).
        asn1::seq('06092A864886F70D010701'). //OBJ_pkcs7_data
        $certs.
        asn1::set($signerinfos)
    );
    $pkcs7ContentInfo = asn1::seq(
        "06092A864886F70D010702". // Hexadecimal form of pkcs7-signedData
        asn1::expl(0,$pkcs7contentSignedData)
    );
    return $pkcs7ContentInfo;
  }
}
