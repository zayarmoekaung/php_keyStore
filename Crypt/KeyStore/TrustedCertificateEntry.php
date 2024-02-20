<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Key store entry interface and implementations.
 *  
 * PHP version 5
 *
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   SVN: $Id: TrustedCertificateEntry.php 6677 2009-11-30 18:05:15Z swamsley $
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */
 
/**
 *
 */
require_once 'Crypt/KeyStore/BaseEntry.php';
 
/**
 * A trusted certificate key store entry that includes a trusted certificate.
 *  
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   Release: 0.1.9dev
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */ 
class Crypt_KeyStore_TrustedCertificateEntry extends Crypt_KeyStore_BaseEntry
{

    private $_trustedCert;
    
    /**
     * Constructs a trusted certificate key store entry with the trusted
     * certificate.
     *      
     * @param Crypt_KeyStore_Certificate $trustedCert the trusted certificate 
     *      stored with entry 
     */         
    public function __construct($trustedCert) 
    {
        parent::__construct(new DateTime('now', new DateTimeZone('UTC')));
        $this->_trustedCert = $trustedCert;
    }
    
    /**
     * Gets the trusted Certficate from this entry.
     *      
     * @return Crypt_KeyStore_Certificate
     */
    public function getTrustedCertificate() 
    {
        return $this->_trustedCert;
    }
    
    /**
     * Returns the type of the key store entry.
     *          
     * @return int
     */         
    public function getEntryType() 
    { 
        return Crypt_KeyStore_BaseEntry::TRUSTEDCERT_TYPE; 
    }
    
    /**
     * Returns a string representation of this 
     * Crypt_KeyStore_TrustedCertificateEntry.
     *      
     * @return string
     */
    public function __toString() 
    {
        return "" . $this->_trustedCert;
    }
    
}

?>
