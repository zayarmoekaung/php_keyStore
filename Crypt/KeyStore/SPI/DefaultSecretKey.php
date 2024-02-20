<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Default implementation of a secret key.
 *  
 * PHP version 5
 *
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   SVN: $Id: DefaultSecretKey.php 6677 2009-11-30 18:05:15Z swamsley $
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */
 
/**
 *
 */
require_once 'Crypt/KeyStore/SecretKey.php';

/**
 * Default implementation of the SecretKey interface for use with mycrypt/mhash.
 *  
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   Release: 0.1.9dev
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */ 
class Crypt_KeyStore_SPI_DefaultSecretKey implements Crypt_KeyStore_SecretKey
{
    private $_keyData;
    
    private $_algorithm;
    
    private $_size;
    
    /**
     * Constructs a DefaultSecretKey using the $keyData and $algorithm.
     * 
     * @param string $keyData   the PEM encoded public key data
     * @param string $algorithm the algorithm used to genereate the key
     * @param int    $size      the size of the key in # of characters
     */
    public function __construct($keyData, $algorithm, $size)
    {
        $this->_keyData   = $keyData;
        $this->_algorithm = $algorithm;
        $this->_size      = $size;
    }
    
    
    /**
     * Returns the standard algorithm name for this key.
     * 
     * @return string the name of the algorithm associated with this key          
     */
    public function getAlgorithm()
    {
        return $this->_algorithm;
    }
    
    /**
     * Returns the size of the key in # of characters. In other words, a 
     * 256-bit key would be 32 characters (8 bits/character).     
     * 
     * @return int the size of key in # of characters.          
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
     * this key does not support encoding. For symmetric, secret keys, the
     * formatting is 'HEX'.    
     * 
     * @return string the primary encoding format of the key
     */
    public function getFormat()
    {
        return 'HEX';
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
