<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Certificate interface implementation for X509 certificates.
 *  
 * PHP version 5
 *
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   SVN: $Id: X509Certificate.php 6677 2009-11-30 18:05:15Z swamsley $
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */
 
/**
 *
 */
require_once 'Crypt/KeyStore/Certificate.php';
require_once 'Crypt/KeyStore/SPI/DefaultPublicKey.php';

/**
 * Certificate interface implementation for X509 certificates.
 *  
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   Release: 0.1.9dev
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */ 
class Crypt_KeyStore_SPI_X509Certificate implements Crypt_KeyStore_Certificate
{
    /**
     * The PEM encoded certificate.
     */         
    private $_rawCert;
    
    /**
     * Constructs an X509Certificate using the PEM-encoded certificate data.
     * 
     * @param string $rawCert - PEM-encoded certificate data          
     */
    public function __construct($rawCert)
    {
        $this->_rawCert = $rawCert;
    }
    
    /**
     * Returns the encoded form of this certificate. 
     * 
     * @return string the encoded form of this certificate          
     */
    public function getEncoded()
    {
        return $this->_rawCert;
    }
    
    /**
     * Gets the public key from this certificate.
     * 
     * @return Crypt_KeyStore_PublicKey          
     */
    public function getPublicKey()
    {
        $pubKey  = null;
        $certRes = openssl_x509_read($this->_rawCert);
        if ($certRes != false) {
            $keyRes = openssl_pkey_get_public($certRes);
            if ($keyRes != false) {
                $keyData = openssl_pkey_get_details($keyRes);
                if ($keyData != false) {
                    $theKey  = $keyData['key'];
                    $keyType = $keyData['type'];
                    $pubKey  = new Crypt_KeyStore_SPI_DefaultPublicKey($theKey, 
                            $keyType);
                }
            }
            openssl_free_key($keyRes);
        }
        openssl_x509_free($certRes);
        return $pubKey;
    }
    
    /**
     * Returns the type of this certificate. For this implementation, the type
     * will be one of the OpenSSL certificate types:
     * <ul>     
     * <li>OPENSSL_KEYTYPE_RSA,</li>
     * <li>OPENSSL_KEYTYPE_DSA,</li>
     * <li>OPENSSL_KEYTYPE_DH</li>
     * <li>OPENSSL_KEYTYPE_EC, or</li>
     * <li>-1, meaning unknown</li>
     * </ul>               
     * 
     * @return string the type of this certificate.          
     */
    public function getType()
    {
        $keyType = null;
        $certRes = openssl_x509_read($this->_rawCert);
        if ($certRes != false) {
            $keyRes = openssl_pkey_get_public($certRes);
            if ($keyRes != false) {
                $keyData = openssl_pkey_get_details($keyRes);
                if ($keyData != false) {
                    $keyType = $keyData['type'];
                }
            }
            openssl_free_key($keyRes);
        }
        openssl_x509_free($certRes);
        return $keyType;
    }
    
    /**
     * Returns true if and only if this certificate is the same certificate
     * as the Certificate object pointed to by $rhsCert.
     * 
     * @param Crypt_KeyStore_Certificate $rhsCert certificate to compare to this 
     *      certificated
     * 
     * @return boolean true if $this == $rhsCert, false if not
     */
    public function isEqualTo($rhsCert)
    {
        $result = false;
        if (!is_null($rhsCert)
            && $rhsCert instanceof Crypt_KeyStore_SPI_X509Certificate
        ) {
            $result = ($this->_rawCert == $rhsCert->getEncoded());
        }
        return $result;
    }
    
    /**
     * Returns a string representation of this certificate.
     *          
     * @return string
     */         
    public function __toString()
    {
        return $this->_rawCert;
    }
}
?>
