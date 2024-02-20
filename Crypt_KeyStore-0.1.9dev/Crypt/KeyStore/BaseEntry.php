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
 * @version   SVN: $Id: BaseEntry.php 6677 2009-11-30 18:05:15Z swamsley $
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */

/**
 *
 */
require_once 'Crypt/KeyStore/Entry.php';
 
/**
 * Abstract base implementation of the key store entry interface.
 *  
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   Release: 0.1.9dev
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */ 
abstract class Crypt_KeyStore_BaseEntry implements Crypt_KeyStore_Entry
{
    const PRIVATEKEY_TYPE = 0;
    
    const SECRETKEY_TYPE = 1;
    
    const TRUSTEDCERT_TYPE = 2;

    private $_creationDate;
    
    /**
     * Constructs a new base key store entry.
     * 
     * @param DateTime $creationDate date/time the key store entry was created
     */              
    public function __construct($creationDate) 
    {
        $this->_creationDate = $creationDate;
    }
    
    /**
     * Returns the date/time stamp the key store entry was added to the key
     * store.
     *      
     * @return DateTime
     *          
     * @see Crypt_KeyStore_Entry#getCreationDate()
     */
    public function getCreationDate() 
    {
        return $this->_creationDate;
    }
}

?>
