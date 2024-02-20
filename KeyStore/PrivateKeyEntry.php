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
 * @version   SVN: $Id: PrivateKeyEntry.php 6677 2009-11-30 18:05:15Z swamsley $
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */
 
/**
 *
 */
require_once 'Crypt/KeyStore/BaseEntry.php';
 
/**
 * An asymmetric private key key store entry that includes a public 
 * certificate, a private key, and optionally a certificate chain. 
 *  
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   Release: 0.1.9dev
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */ 
class Crypt_KeyStore_PrivateKeyEntry extends Crypt_KeyStore_BaseEntry
{

    /**
     * The PrivateKey object.
     */         
    private $_privKey;
    
    /**
     * The Certificate object.
     */         
    private $_cert;
    
    /**
     * An array of Certificate objects.
     */         
    private $_chain;
    
    /**
     * Contructs a private key key store entry.
     *      
     * @param Crypt_KeyStore_PrivateKey         $privKey private key
     * @param Crypt_KeyStore_Certificate        $cert    public key 
     * @param array<Crypt_KeyStore_Certificate> $chain   array of certificates
     */
    public function __construct($privKey, $cert, $chain=array()) 
    {
        parent::__construct(new DateTime('now', new DateTimeZone('UTC')));
        $this->_privKey = $privKey;
        $this->_cert    = $cert;
        $this->_chain   = $chain;
    }
    
    /**
     * Gets the end entity Certificate from the certificate chain 
     * in this entry.
     *      
     * @return Crypt_KeyStore_Certificate
     */
    public function getCertificate() 
    {
        return $this->_cert;
    }

    /**
     * Gets the Certificate chain from this entry.
     *      
     * @return array<Crypt_KeyStore_Certificate>
     */
    public function getCertificateChain() 
    {
        return $this->_chain;
    }
 
    /**
     * Gets the PrivateKey from this entry.
     *      
     * @return Crypt_KeyStore_PrivateKey
     */
    public function getPrivateKey() 
    {
        return $this->_privKey;
    }

    /**
     * Returns the type of the key store entry.
     * 
     * @return int
     */         
    public function getEntryType() 
    { 
        return Crypt_KeyStore_BaseEntry::PRIVATEKEY_TYPE; 
    }
    
    /**
     * Returns a string representation of this Crypt_KeyStore_PrivateKeyEntry.
     *      
     * @return string
     */
    public function __toString()
    {
        $out = '';
        $tmp = '';
        
        $out .= $this->_privKey;
        $out .= ",";
        $out .= $this->_cert;
        
        return $out;
    }

}

?>
