<?php

/**
 * Interface for keys (symmetric or asymmetric) stored by the key store.
 *  
 * PHP version 5
 *
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   SVN: $Id: Key.php 6677 2009-11-30 18:05:15Z swamsley $
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */
 
/**
 * Interface for keys (symmetric or asymmetric) stored by the key store.
 *  
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   Release: 0.1.9dev
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */ 
interface Crypt_KeyStore_Key
{
    /**
     * Returns the standard algorithm name for this key. For example, "DSA" 
     * would indicate that this key is a DSA key.
     * 
     * @return string the name of the algorithm associated with this key          
     */
    public function getAlgorithm();
    
    /**
     * Returns the key in its primary encoding format, or null if this key does 
     * not support encoding.
     *          
     * @return string the encoded key, or null if the key does not support encoding.
     */
    public function getEncoded();
    
    /**
     * Returns the name of the primary encoding format of this key, or null if 
     * this key does not support encoding. The primary encoding format is named 
     * in terms of the appropriate ASN.1 data format, if an ASN.1 specification 
     * for this key exists. For example, the name of the ASN.1 data format for
     * public keys is SubjectPublicKeyInfo, as defined by the X.509 standard; 
     * in this case, the returned format is "X.509". Similarly, the name of the 
     * ASN.1 data format for private keys is PrivateKeyInfo, as defined by the 
     * PKCS #8 standard; in this case, the returned format is "PKCS#8".
     * 
     * @return string the primary encoding format of the key
     */
    public function getFormat();
}
?>
