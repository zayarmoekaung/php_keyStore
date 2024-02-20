<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Default private key interface implementation.
 *  
 * PHP version 5
 *
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   SVN: $Id: DefaultPrivateKey.php 6677 2009-11-30 18:05:15Z swamsley $
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */
 
/**
 *
 */
require_once 'Crypt/KeyStore/PrivateKey.php';

/**
 * PrivateKey implementation for use with OpenSSL extension where the encoded
 * format is PEM X509. 
 *  
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   Release: 0.1.9dev
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */ 
class Crypt_KeyStore_SPI_DefaultPrivateKey implements Crypt_KeyStore_PrivateKey
{
    private $_keyData;
    
    private $_algorithm;
    
    private $_size;
    
    /**
     * Constructs an DefaultPrivateKey using the $keyData and $algorithm.
     * 
     * @param string $keyData   the PEM encoded public key data
     * @param string $algorithm the algorithm used to genereate the key
     * @param int    $size      the size of the key in bits
     */         
    public function __construct($keyData, $algorithm, $size)
    {
        $this->_keyData   = $keyData;
        $this->_algorithm = $algorithm;
        $this->_size      = $size;
    }
    
    /**
     * Returns the standard algorithm name for this key. For example, "DSA" 
     * would indicate that this key is a DSA key.
     * 
     * @return string the name of the algorithm associated with this key          
     */
    public function getAlgorithm()
    {
        return $this->_algorithm;
    }
    
    /**
     * Returns the size of the key, in bits.
     * 
     * @return int          
     */         
    public function getSize() 
    {
        return $this->_size;
    }
    
    /**
     * Returns the key in its primary encoding format, or null if this key does 
     * not support encoding.
     *          
     * @return string the encoded key, or null if the key does not support encoding.
     */
    public function getEncoded()
    {
        return $this->_keyData;
    }
    
    /**
     * Returns the name of the primary encoding format of this key, or null if 
     * this key does not support encoding. For default private keys, the format
     * is 'X509'.
     * 
     * @return string the primary encoding format of the key
     */
    public function getFormat()
    {
        return 'X509';
    }
    
    /**
     * Returns a string representation of this key.
     * 
     * @return string
     */          
    public function __toString()
    {
        return $this->_keyData;
    }
}
?>
