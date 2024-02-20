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
 * @version   SVN: $Id: SecretKeyEntry.php 6677 2009-11-30 18:05:15Z swamsley $
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */
 
/**
 *
 */
require_once 'Crypt/KeyStore/BaseEntry.php';
 
/**
 * A symmetric key key store entry that includes a secret key.
 *  
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   Release: 0.1.9dev
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */ 
class Crypt_KeyStore_SecretKeyEntry extends Crypt_KeyStore_BaseEntry
{

    /**
     * The secret key data, which is hex-encoded. The secret key may be encrypted
     * with a pass phrase. If so, the first 8 bytes of the secret key data will
     * be the IV, the next eight bytes will be the salt, and the remaining data
     * will be the secret key data itself.               
     */         
    private $_secretKey;
    
    /**
     * Constructs a secret key key store entry with the secret key.
     *      
     * @param Crypt_KeyStore_SecretKey $secretKey the symmetric secret key to 
     *      store with entry 
     */
    public function __construct($secretKey) 
    {
        parent::__construct(new DateTime('now', new DateTimeZone('UTC')));
        $this->_secretKey = $secretKey;
    }
    
    /**
     * Gets the SecretKey from this entry.
     *      
     * @return Crypt_KeyStore_SecretKey
     */
    public function getSecretKey() 
    {
        return $this->_secretKey;
    }
    
    /**
     * Returns the type of the key store entry.
     *          
     * @return int
     */         
    public function getEntryType() 
    { 
        return Crypt_KeyStore_BaseEntry::SECRETKEY_TYPE; 
    }
    
    /**
     * Returns a string representation of this Crypt_KeyStore_SecretKeyEntry.
     *      
     * @return string
     */
    public function __toString() 
    {
        return "" . $this->_secretKey;
    }

}

?>
