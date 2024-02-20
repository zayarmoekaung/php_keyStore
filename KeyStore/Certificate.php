<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Defines the interface for certificates.
 *  
 * PHP version 5
 *
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   SVN: $Id: Certificate.php 6677 2009-11-30 18:05:15Z swamsley $
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */
 
/**
 *
 */
require_once 'Crypt/KeyStore/Key.php';

/**
 * Abstract interface definition of a certificate type.
 * 
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   Release: 0.1.9dev
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */ 
interface Crypt_KeyStore_Certificate
{
    /**
     * Returns the encoded form of this certificate. It is assumed that each 
     * certificate type would have only a single form of encoding; for example, 
     * X.509 certificates would be encoded as PEM.
     * 
     * @return string the encoded form of this certificate          
     */
    public function getEncoded();
    
    /**
     * Gets the public key from this certificate.
     * 
     * @return Crypt_KeyStore_PublicKey          
     */
    public function getPublicKey();
    
    /**
     * Returns the type of this certificate.
     * 
     * @return string the type of this certificate.          
     */
    public function getType();
    
    /**
     * Returns true if and only if this certificate is the same certificate
     * as the Certificate object pointed to by $rhsCert.
     * 
     * @param Crypt_KeyStore_Certificate $rhsCert certificate to compare to this 
     *      certificate               
     * 
     * @return boolean true if $this == $rhsCert, false if not
     */         
    public function isEqualTo($rhsCert);
}
?>
