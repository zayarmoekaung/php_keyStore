<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Default SPI implemetation.
 * 
 * Default implementation of the service provider interface using mhash, mcrypt,
 * and OpenSSL for cryptographic and PKI functionality and files for storage. 
 *  
 * PHP version 5
 *
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   SVN: $Id: DefaultKeyStore.php 6677 2009-11-30 18:05:15Z swamsley $
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */ 

/**
 * 
 */
require_once 'Crypt/KeyStore/SPI/KeyStoreSPI.php';
require_once 'Crypt/KeyStore/SPI/DefaultSecretKey.php';
require_once 'Crypt/KeyStore/SPI/DefaultPrivateKey.php';
require_once 'Crypt/KeyStore/SPI/DefaultPublicKey.php';
require_once 'Crypt/KeyStore/SPI/X509Certificate.php';
require_once 'Crypt/KeyStore/Exception.php';
require_once 'Crypt/KeyStore/PrivateKeyEntry.php';
require_once 'Crypt/KeyStore/SecretKeyEntry.php';
require_once 'Crypt/KeyStore/TrustedCertificateEntry.php';
require_once 'Log.php';

/**
 * Default SPI implemetation.
 * 
 * Default implementation of the service provider interface using mhash, mcrypt,
 * and OpenSSL for cryptographic and PKI functionality and files for storage. 
 * 
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   Release: 0.1.9dev
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */ 
class Crypt_KeyStore_SPI_DefaultKeyStore implements Crypt_KeyStore_SPI_KeyStoreSPI
{
    /**
     * Generic key-type constants.
     */
              
    const KEYTYPE_RSA = 'RSA';
    const KEYTYPE_DSA = 'DSA';
    const KEYTYPE_DH  = 'DH';
    
    /**
     * Generic hash algorithm constants.
     */
              
    const HASH_ADLER32   = 'ADLER32';
    const HASH_CRC32     = 'CRC32';
    const HASH_CRC32B    = 'CRC32B';
    const HASH_GOST      = 'GOST';
    const HASH_HAVAL128  = 'HAVAL128';
    const HASH_HAVAL160  = 'HAVAL160';
    const HASH_HAVAL192  = 'HAVAL192';
    const HASH_HAVAL256  = 'HAVAL256';
    const HASH_MD2       = 'MD2';
    const HASH_MD4       = 'MD4';
    const HASH_MD5       = 'MD5';
    const HASH_RIPEMD160 = 'RIPEMD160';
    const HASH_SHA1      = 'SHA1';
    const HASH_SHA256    = 'SHA256';
    const HASH_TIGER     = 'TIGER';
    const HASH_TIGER128  = 'TIGER128';
    const HASH_TIGER160  = 'TIGER160';

    /**
     * Generic digest signature constants.
     */
              
    const SIGNATURE_SHA1 = 'SHA1';
    const SIGNATURE_MD5  = 'MD5';
    const SIGNATURE_MD4  = 'MD4';
    const SIGNATURE_MD2  = 'MD2';
    
    /**
     * Generic cipher mode constants.
     */
              
    const MODE_ECB    = 'ECB';
    const MODE_CBC    = 'CBC';
    const MODE_CFB    = 'CFB';
    const MODE_OFB    = 'OFB';
    const MODE_NOFB   = 'NOFB';
    const MODE_STREAM = 'STREAM';
    
    /**
     * Generic cipher algorithm constants.
     */
              
    const CIPHER_3DES       = '3DES';
    const CIPHER_ARCFOUR_IV = 'ARCFOUR_IV';
    const CIPHER_ARCFOUR    = 'ARCFOUR';
    const CIPHER_BLOWFISH   = 'BLOWFISH';
    const CIPHER_CRYPT      = 'CRYPT';
    const CIPHER_DES        = 'DES';
    const CIPHER_GOST       = 'GOST';
    const CIPHER_IDEA       = 'IDEA';
    const CIPHER_LOKI97     = 'LOKI97';
    const CIPHER_MARS       = 'MARS';
    const CIPHER_PANAMA     = 'PANAMA';
    const CIPHER_RC2        = 'RC2';
    const CIPHER_RC6        = 'RC6';
    const CIPHER_SAFERPLUS  = 'SAFERPLUS';
    const CIPHER_SERPENT    = 'SERPENT';
    const CIPHER_SKIPJACK   = 'SKIPJACK';
    const CIPHER_THREEWAY   = 'THREEWAY';
    const CIPHER_TRIPLEDES  = 'TRIPLEDES';
    const CIPHER_TWOFISH    = 'TWOFISH';
    const CIPHER_WAKE       = 'WAKE';
    const CIPHER_XTEA       = 'XTEA';
    
    /**
     * Option key contants.
     */
    
    /**
     * Option key for the cipher algorithm.
     */         
    const OPT_CIPHER = 'cipher';
    
    /**
     * Option key for the hash algorithm.
     */         
    const OPT_HASH = 'hash';
    
    /**
     * Option key for the cipher mode.
     */         
    const OPT_MODE = 'mode';
    
    /**
     * Option key for the key size.
     */         
    const OPT_KEYSIZE = 'keysize';
    
    /**
     * Option key for the salt size.
     */         
    const OPT_SALTSIZE = 'saltsize';
    
    /**
     * Option key for the message digest/signature algorithm.
     */         
    const OPT_DIGEST = 'digest';
    
    /**
     * Option key for the key type.
     */
    const OPT_KEYTYPE = 'keytype';
    
    /**
     * Option key for the certificate days.
     */         
    const OPT_CERT_DAYS = 'days';

    /**
     * Mapping of generic cipher constants to mycrypt cipher constants.
     */         
    private static $_cipherTable = array(self::CIPHER_3DES => MCRYPT_3DES,
            self::CIPHER_ARCFOUR_IV => MCRYPT_ARCFOUR_IV,
            self::CIPHER_ARCFOUR => MCRYPT_ARCFOUR,
            self::CIPHER_BLOWFISH => MCRYPT_BLOWFISH,
            self::CIPHER_CRYPT => MCRYPT_CRYPT,
            self::CIPHER_DES => MCRYPT_DES,
            self::CIPHER_GOST => MCRYPT_GOST,
            self::CIPHER_IDEA => MCRYPT_IDEA,
            self::CIPHER_LOKI97 => MCRYPT_LOKI97,
            self::CIPHER_MARS => MCRYPT_MARS,
            self::CIPHER_PANAMA => MCRYPT_PANAMA,
            self::CIPHER_RC2 => MCRYPT_RC2,
            self::CIPHER_RC6 => MCRYPT_RC6,
            self::CIPHER_SAFERPLUS => MCRYPT_SAFERPLUS,
            self::CIPHER_SERPENT => MCRYPT_SERPENT,
            self::CIPHER_SKIPJACK => MCRYPT_SKIPJACK,
            self::CIPHER_THREEWAY => MCRYPT_THREEWAY,
            self::CIPHER_TRIPLEDES => MCRYPT_TRIPLEDES,
            self::CIPHER_TWOFISH => MCRYPT_TWOFISH,
            self::CIPHER_WAKE => MCRYPT_WAKE,
            self::CIPHER_XTEA => MCRYPT_XTEA);

    /**
     * Mapping of generic hash constants to mhash hash constants.
     */         
    private static $_hashTable = array(self::HASH_ADLER32 => MHASH_ADLER32,
            self::HASH_CRC32 => MHASH_CRC32,
            self::HASH_CRC32B => MHASH_CRC32B,
            self::HASH_GOST => MHASH_GOST,
            self::HASH_HAVAL128 => MHASH_HAVAL128,
            self::HASH_HAVAL160 => MHASH_HAVAL160,
            self::HASH_HAVAL192 => MHASH_HAVAL192,
            self::HASH_HAVAL256 => MHASH_HAVAL256,
            self::HASH_MD4 => MHASH_MD4,
            self::HASH_MD5 => MHASH_MD5,
            self::HASH_RIPEMD160 => MHASH_RIPEMD160,
            self::HASH_SHA1 => MHASH_SHA1,
            self::HASH_SHA256 => MHASH_SHA256,
            self::HASH_TIGER => MHASH_TIGER,
            self::HASH_TIGER128 => MHASH_TIGER128,
            self::HASH_TIGER160 => MHASH_TIGER160);
       
    /**
     * Mapping of generic mode constants to mcrypt mode constants.
     */         
    private static $_modeTable = array(self::MODE_ECB => MCRYPT_MODE_ECB,
            self::MODE_CBC => MCRYPT_MODE_CBC,
            self::MODE_CFB => MCRYPT_MODE_CFB,
            self::MODE_OFB => MCRYPT_MODE_OFB,
            self::MODE_NOFB => MCRYPT_MODE_NOFB,
            self::MODE_STREAM => MCRYPT_MODE_STREAM);
            
    /**
     * Mapping of generic digest constants to OpenSSL digest constants.
     */         
    private static $_digestTable = array(self::HASH_SHA1 => OPENSSL_ALGO_SHA1,
            self::HASH_MD5 => OPENSSL_ALGO_MD5,
            self::HASH_MD4 => OPENSSL_ALGO_MD4,
            self::HASH_MD2 => OPENSSL_ALGO_MD2);
            
    /**
     * Mapping of generic key-type constants to OpenSSL key-type constants.
     */         
    private static $_keyTypeTable = array(self::KEYTYPE_RSA => OPENSSL_KEYTYPE_RSA,
            self::KEYTYPE_DSA => OPENSSL_KEYTYPE_DSA,
            self::KEYTYPE_DH => OPENSSL_KEYTYPE_DH);

    /**
     * Option names and their default values for symmetric crypto ops.
     */
    private static $_symmetricOptions = array(
        self::OPT_CIPHER => self::CIPHER_TWOFISH,
        self::OPT_HASH => self::HASH_SHA256,
        self::OPT_MODE => self::MODE_CBC,
        self::OPT_KEYSIZE => 32,
        self::OPT_SALTSIZE => 8
    );
    
    /**
     * Option names and their default values for asymmetric crypto ops.
     */
    private static $_asymmetricOptions = array(
        self::OPT_DIGEST => self::SIGNATURE_SHA1,
        self::OPT_KEYTYPE => self::KEYTYPE_RSA,
        self::OPT_KEYSIZE => 2048,
        self::OPT_CERT_DAYS => 30
    );
        
    /**
     * The type of the key store (i.e., PKS, etc.).
     */         
    private $_type;
    
    /**
     * Array of key store entries (Crypt_KeyStoreEntry instances).
     */         
    private $_entries = array();
    
    /**
     * Default, no-argument contructor.
     */
    public function __construct() 
    {
        $this->_type = 'PKS';
    }
    
    /**
     * Internal logging method.
     * 
     * @param string $msg   the message to log
     * @param int    $level the level at which to log the message
     * 
     * @return void                        
     */         
    private function _log($msg, $level=PEAR_LOG_DEBUG) 
    {
        $logger = &Log::singleton(
            'console', 
            '', 
            'Crypt_KeyStore', 
            PEAR_LOG_ERR
        );
        $logger->log($msg, $level);
        return;
    }
    
    /**
     * Lists all the alias names of this Crypt_KeyStore.
     * 
     * @return array<string> array of alias strings
     */
    public function aliases() 
    {
        $aliases = array();
        foreach ($this->_entries as $alias => $key) {
            $aliases[] = $alias;
        }
        return $aliases;
    }
    
    /**
     * Checks if the given alias exists in this Crypt_KeyStore.
     *      
     * @param string $alias the alias of the entry to query
     *      
     * @return boolean true if the key store contains an entry with the alias,
     *      false if not     
     */
    public function containsAlias($alias) 
    {
        return isset($this->_entries[$alias]);
    }
    
    /**
     * Deletes the entry identified by the given alias from this Crypt_KeyStore.
     *      
     * @param string $alias the alias of the entry to delete
     * 
     * @return void          
     */
    public function deleteEntry($alias) 
    {
        unset($this->_entries[$alias]);
        return;
    }
    
    /**
     * Determines if the Crypt_KeyStore Entry for the specified alias is an 
     * instance or subclass of the specified entryClass.
     *      
     * @param string $alias          the alias of the entry to test
     * @param class  $entryClazzName the key store entry class name to test
     *      
     * @return boolean true if entry is instance of the class name, false if not
     */
    public function entryInstanceOf($alias, $entryClazzName) 
    {
        $rv = false;
        if ($this->containsAlias($alias)) {
            $entry = $this->_entries[$alias];
            $rv    = ($entry instanceof $entryClazzName);
        }
        return $rv;
    }
    
    /**
     * Returns the (alias) name of the first Crypt_KeyStore entry whose certificate 
     * matches the given certificate.
     *      
     * @param string $cert the certificate text
     *      
     * @return Crypt_KeyStore_Certificate the alias of the certificate
     */
    public function getCertificateAlias($cert) 
    {
        $rv    = '';
        $found = false;
        
        foreach ($this->_entries as $alias => $entry) {
        
            switch ($entry->getEntryType()) {
            case Crypt_KeyStore_BaseEntry::PRIVATEKEY_TYPE:
                if ($entry->getCertificate()->isEqualTo($cert)) {
                    $rv    = $alias;
                    $found = true;
                }
                break;
            case Crypt_KeyStore_BaseEntry::TRUSTEDCERT_TYPE:
                if ($entry->getTrustedCertificate()->isEqualTo($cert)) {
                    $rv    = $alias;
                    $found = true;
                }
                break;
            default:
                break;
            }
            
            // if we found our cert, break the loop
            if ($found == true) {
                break;
            }
        }
        
        return $rv;
    }
    
    /**
     * Returns the certificate chain associated with the given alias.
     *      
     * @param string $alias the alias of the certificate chain
     *      
     * @return array an array of certificates in the chain, or NULL if the 
     *         chain does not exist for the the alias     
     */
    public function getCertificateChain($alias) 
    {
        $chain = null;
        if ($this->containsAlias($alias)) {
            $entry = $this->getEntry($alias);
            switch ($entry->getEntryType()) {
            case Crypt_KeyStore_BaseEntry::PRIVATEKEY_TYPE:
                $chain = $entry->getCertificateChain();
                break;
            default:
                throw new Crypt_KeyStore_Exception("Entry $alias is not a "
                        . "private key entry");
                break;
            }
        }
        
        return $chain;
    }
    
    /** 
     * Returns the creation date of the entry identified by the given alias.
     *      
     * @param string $alias the alias of the entry to retrieve
     *      
     * @return DateTime the date/time the key was added to the key store
     */
    public function getCreationDate($alias) 
    {
        $date = null;
        if ($this->containsAlias($alias)) {
            $entry = $this->_entries[$alias];
            $date  = $entry->getCreationDate();
        }
        return $date;
    }
    
    /** 
     * Gets a Crypt_KeyStore Entry for the specified alias with the specified 
     * protection parameter.
     *      
     * @param string $alias   the alias of the entry to retrieve
     * @param array  $options the password used to decrypt the key
     *      
     * @return Crypt_KeyStore_Entry 
     */
    public function getEntry($alias, $options=false) 
    {
        return $this->_entries[$alias];
    }
    
    /**
     * Returns the key associated with the given alias, using the given password 
     * to decrypt it.
     *      
     * @param string $alias    the alias of the entry to retrieve
     * @param array  $password the password used to decrypt the key
     *      
     * @return string the unprotected key, or null on failure
     */
    private function _getKey($alias, $password=false) 
    {
        $key       = null;
        $decrypted = null;
        
        if ($this->containsAlias($alias)) {
        
            $entry = $this->_entries[$alias];
            
            switch ($entry->getEntryType()) {
            case Crypt_KeyStore_BaseEntry::PRIVATEKEY_TYPE:
            
                // for private keys, use OpenSSL to export the key resource
                // and decrypt it
                $this->_log("Getting private key for alias $alias");
                $key = $entry->getPrivateKey()->getEncoded();
                if ($password != false) {
                    $this->_log("Getting key for alias $alias with password");
                    $decrypted = openssl_get_privatekey($key, $password);
                } else {
                    $this->_log("Getting key for alias $alias without password");
                    $decrypted = openssl_get_privatekey($key);
                }
                break;
                
            case Crypt_KeyStore_BaseEntry::SECRETKEY_TYPE:
            
                // for secret keys, decrypt with the password using mcrypt
                $this->_log("Getting secret key for alias $alias");
                $key = $entry->getSecretKey()->getEncoded();
                if ($key != null && $password != false) {
                
                    $this->_log("Decrypting secret key for alias $alias");
                    
                    $options       = array(self::OPT_CIPHER => 
                                    $entry->getSecretKey()->getAlgorithm(),
                            self::OPT_KEYSIZE => $entry->getSecretKey()->getSize(),
                            self::OPT_SALTSIZE => 8);
                    $processedOpts = $this->_processSymmetricOptions($options);
                    try {
                    
                        // not only do we have key, we have a password - 
                        // decrypt the key!
                        // Open the cipher 
                        $td = mcrypt_module_open(
                            $processedOpts[self::OPT_CIPHER], 
                            '', 
                            $processedOpts[self::OPT_MODE], 
                            ''
                        );
                        
                        // the IV and salt are at the beginning of the password 
                        // protected key the size of the iv and salt are cipher 
                        // dependent - use the constants!
                        $ivsize = mcrypt_enc_get_iv_size($td);
                        $iv     = pack(
                            'H*', 
                            substr(
                                $key, 
                                0, 
                                $ivsize * 2
                            )
                        );
                        $salt   = pack(
                            'H*', 
                            substr(
                                $key, 
                                $ivsize * 2, 
                                $processedOpts[self::OPT_SALTSIZE] * 2
                            )
                        );
                        
                        $this->_log("_getKey(): iv=" . bin2hex($iv));
                        $this->_log("_getKey(): salt=" . bin2hex($salt));
                        
                        // the key data is the remaining data after the IV and salt 
                        // the size of the iv and salt are cipher dependent
                        // multiply byte-sizes by 2 because hex-encoding doubles the
                        // size of each byte
                        $header_size = ($ivsize * 2)
                                + ($processedOpts[self::OPT_SALTSIZE] * 2);
                        $encoded_key = substr($key, $header_size);
                        $this->_log("_getKey() header_size=$header_size");
                        $this->_log("_getKey() encoded_key=$encoded_key");
                        $encKey = pack('H*', $encoded_key);
                        
                        /* Create decryption key from the salt and password */
                        $dec_key = mhash_keygen_s2k(
                            $processedOpts[self::OPT_HASH], 
                            $password, 
                            $salt, 
                            mcrypt_enc_get_key_size($td)
                        );
                        
                        /* Intialize encryption from the IV and decryption_key */
                        mcrypt_generic_init($td, $dec_key, $iv);
                        
                        /* Decrypt encrypted key */
                        $decrypted = mdecrypt_generic($td, $encKey);
                        
                        /* Terminate encryption handler */
                        mcrypt_generic_deinit($td);
                        mcrypt_module_close($td);
                    }
                    catch (Exception $e) {
                        throw new Crypt_KeyStore_Exception($e);
                    }
                } else {
                    // if no password is provided, ass_ume the key is plaintext and 
                    // return it - the client is to assume responsibility if it is 
                    // still encrypted and deal with his shame
                    $decrypted = $key;
                }
                break;
            default:
                throw new Crypt_KeyStore_Exception("Entry for alias $alias "
                        . "is not a key entry");
                break;
            }
        } else {
            throw new Crypt_KeyStore_Exception("Entry for alias $alias "
                    . "is not in this Crypt_KeyStore"); 
        }
        
        return $decrypted;
    }
    
    /**
     * Returns the type of this Crypt_KeyStore.
     *      
     * @return string the type of key store implementation
     */
    public function getType() 
    {
         return $this->_type;
    }
    
    /**
     * Returns true if the entry identified by the given alias is a 
     * Crypt_KeyStore_TrustedCertificateEntry.
     *      
     * @param string $alias the alias of the entry to test
     *      
     * @return boolean true if entry is a certificate, false if not
     */
    public function isCertificateEntry($alias) 
    {
        $rv = false;
        if ($this->containsAlias($alias)) {
            $entry = $this->_entries[$alias];
            $type = $entry->getEntryType();
            if ($type == Crypt_KeyStore_BaseEntry::PRIVATEKEY_TYPE 
                || $type == Crypt_KeyStore_BaseEntry::TRUSTEDCERT_TYPE
            ) {
                $rv = true;
            }
        }
        return $rv;
    }
    
    /**
     * Returns true if the entry identified by the given alias was is a
     * Crypt_KeyStore_PrivateKeyEntry or a Crypt_KeyStore_SecretKeyEntry.
     *      
     * @param string $alias the alias of the entry to test
     *      
     * @return boolean true if entry is a key, false if not
     */
    public function isKeyEntry($alias) 
    {
        $rv = false;
        if ($this->containsAlias($alias)) {
            $entry = $this->_entries[$alias];
            $type = $entry->getEntryType();
            if ($type == Crypt_KeyStore_BaseEntry::SECRETKEY_TYPE
                || $type == Crypt_KeyStore_BaseEntry::PRIVATEKEY_TYPE
            ) {
                $rv = true;         
            }
        }
        return $rv;
    }
    
    /**
     * Assigns the given trusted certificate to the given alias.
     *      
     * @param string $alias the alias the entry will be stored as 
     * @param string $cert  the certificate to set
     * 
     * @return void
     *                
     * @exception Crypt_KeyStore_Exception
     */
    private function _setCertificateEntry($alias, $cert) 
    {
        if ($this->containsAlias($alias) 
            && !$this->isCertificateEntry($alias)
        ) {
            throw new Crypt_KeyStore_Exception("$alias is not a certificate entry");
        }
        $this->_setEntry(
            $alias, 
            new Crypt_KeyStore_TrustedCertificateKey(
                new Crypt_KeyStore_SPI_X509Certificate($cert)
            )
        );
        return;
    }
    
    /**
     * Assigns the given key to the given alias, protecting it with the given 
     * password, if specified.
     *      
     * @param string $alias the alias the entry will be stored as 
     * @param string $key   the key to set
     * @param string $algo  key algorithm
     * @param int    $size  key size in bits
     * @param string $cert  the public certificate to store
     * @param array  $chain array of certificates from the chain file, 
     *      including the public key certificate     
     * 
     * @return void
     * 
     * @exception Crypt_KeyStore_Exception     
     */
    private function _setKeyEntry($alias, 
        $key,
        $algo,
        $size, 
        $cert, 
        $chain=array()
    ) {
        if ($this->containsAlias($alias) 
            && !$this->isKeyEntry($alias)
        ) {
            throw new Crypt_KeyStore_Exception(
                "Existing entry $alias is not a private or secret key entry");
        }
        
        if (!is_array($chain) || count($chain) == 0) {
            $chain = array($cert);
        }
        
        $chainCerts = array();
        foreach ($chain as $chainCert) {
            $chainCerts[] = new Crypt_KeyStore_SPI_X509Certificate($chainCert);
        }
        
        $this->_setEntry(
            $alias, 
            new Crypt_KeyStore_PrivateKeyEntry(
                new Crypt_KeyStore_SPI_DefaultPrivateKey($key, 
                        $algo, 
                        $size), 
                new Crypt_KeyStore_SPI_X509Certificate($cert), 
                $chainCerts
            )
        );
        return;
    }
    
    /**
     * Assigns the given key to the given alias, protecting it with the given 
     * password, if specified.
     *      
     * @param string $alias the alias the entry will be stored as 
     * @param string $key   the key to set
     * @param string $algo  algorithm used to generate/encrypt key
     * @param int    $size  size of key in bits
     * 
     * @return void
     * 
     * @exception Crypt_KeyStore_Exception     
     */
    private function _setSecretKeyEntry($alias, $key, $algo, $size) 
    {
        if ($this->containsAlias($alias) 
            && !$this->isKeyEntry($alias)
        ) {
             throw new Crypt_KeyStore_Exception("Entry $alias is not a key entry");
        }
        $this->_setEntry(
            $alias, 
            new Crypt_KeyStore_SecretKeyEntry(
                new Crypt_KeyStore_SPI_DefaultSecretKey($key, 
                        $algo, 
                        $size
                )
            )
        );
        return;
    }
    
    /**
     * Saves a Crypt_KeyStore Entry under the specified alias.
     *      
     * @param string               $alias the alias the entry will be stored as 
     * @param Crypt_KeyStore_Entry $entry the entry to set
     * 
     * @return void          
     */
    private function _setEntry($alias, $entry) 
    {
         $this->_entries[$alias] = $entry;
         return;
    }
    
    /**
     * Retrieves the number of entries in this Crypt_KeyStore.
     *      
     * @return int the number of entries in the Crypt_KeyStore instance
     */
    public function size() 
    {
        return count($this->_entries);
    }
                    
    /**
     * Takes an options array and converts into primitive types, setting values
     * to default values where not specified and translates generic options
     * into implementation-specific options.     
     * 
     * @param array $options original options
     * 
     * @return array processed options
     */
    private function _processSymmetricOptions($options)
    {
        $options_out = array();
        
        // copy input to output, filling in default options
        foreach (self::$_symmetricOptions as $optkey => $optval) {
            if (!isset($options[$optkey])) {
                $options_out[$optkey] = $optval;
            } else {
                $options_out[$optkey] = $options[$optkey];
            }
        }
        
        // x-late generic values to mcrypt/mhash values
        foreach ($options_out as $optkey => $optval) {
        
            switch ($optkey) {
            case self::OPT_CIPHER:
                if (isset(self::$_cipherTable[$optval])) {
                    $options_out[$optkey] = self::$_cipherTable[$optval];
                } else {
                    throw new Crypt_KeyStore_Exception("Unsupported cipher: "
                            . "$optval");
                }
                break;
            case self::OPT_HASH:
                if (isset(self::$_hashTable[$optval])) {
                    $options_out[$optkey] = self::$_hashTable[$optval];
                } else {
                    throw new Crypt_KeyStore_Exception("Unsupported hash: "
                            . "$optval");
                }
                break;
            case self::OPT_MODE:
                if (isset(self::$_modeTable[$optval])) {
                    $options_out[$optkey] = self::$_modeTable[$optval];
                } else {
                    throw new Crypt_KeyStore_Exception("Unsupported mode: "
                            . "$optval");
                }
                break;
            }
        }
        
        return $options_out;
    }
    
    /**
     * Takes an options array and converts into primitive types, setting values
     * to default values where not specified and translates generic options
     * into implementation-specific options.     
     * 
     * @param array $options original option array
     * 
     * @return array processed options          
     */         
    private function _processAsymmetricOptions($options)
    {
        $options_out = array();
        
        // copy input to output, filling in default options
        foreach (self::$_asymmetricOptions as $optkey => $optval) {
            if (!isset($options[$optkey])) {
                $options_out[$optkey] = $optval;
            } else {
                $options_out[$optkey] = $options[$optkey];
            }
        }
        
        // x-late generic values to openssl values
        foreach ($options_out as $optkey => $optval) {
        
            switch ($optkey) {
            case self::OPT_DIGEST:
                if (isset(self::$_digestTable[$optval])) {
                    $options_out[$optkey] = self::$_digestTable[$optval];
                } else {
                    throw new Crypt_KeyStore_Exception("Unsupported digest: "
                            . "$optval");
                }
                break;
            case self::OPT_KEYTYPE:
                if (isset(self::$_keyTypeTable[$optval])) {
                    $options_out[$optkey] = self::$_keyTypeTable[$optval];
                } else {
                    throw new Crypt_KeyStore_Exception("Unsupported key type: "
                            . "$optval");
                }
                break;
            }
        }
        
        return $options_out;
    }
    
    /**
     * Creates a symmetric secret key from a randomly generated
     * pass phrase and stores the new key in the key store, protecting it with
     * the password if specified. The pass phrase is a sequence of random hex
     * numbers which is then used to generate the key using a
     * SHA-256 hash and 8-bytes of salt.
     *      
     * @param string $alias    the alias the new key will be stored as
     * @param array  $password [optional] password used to protected key
     * @param array  $options  [optional] key creation options
     * 
     * @return void          
     */
    public function createSecretKey($alias, $password=false, $options=array()) 
    {
        if (!isset($alias) || $alias == '') {
            throw new Crypt_KeyStore_Exception("Alias must be specified");
        }
        
        $processedOpts = $this->_processSymmetricOptions($options);
        $size          = $processedOpts[self::OPT_KEYSIZE];
        
        try {
            
            // create a random keyphrase and create the key with salt
            $keyphrase = '';
            for ($n = 0; $n < $size; $n++) {
                $keyphrase .= dechex(mt_rand(0, 15));
            }
            $salt = substr(
                pack("h*", md5(mt_rand())), 
                0, 
                $processedOpts[self::OPT_SALTSIZE]
            );
            
            // create a big, salted secret key from the random key phrase
            $algoKey = (isset($options[self::OPT_HASH]) ? 
                    $options[self::OPT_HASH] : 
                    self::$_symmetricOptions[self::OPT_HASH]);
            $algo = self::$_hashTable[$algoKey];
            $key = mhash_keygen_s2k($algo, $keyphrase, $salt, $size);
            
            // if specified, encrypt the new key with the specified password
            if ($password != false) {
              
                /* Open the cipher */
                $td = mcrypt_module_open(
                    $processedOpts[self::OPT_CIPHER], 
                    '', 
                    $processedOpts[self::OPT_MODE], 
                    ''
                );
                
                /* Create the IV and determine the keysize length, use MCRYPT_RAND
                 * on Windows instead */
                $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
                $this->_log("createSecretKey(): iv=" . bin2hex($iv));
                $salt = substr(
                    pack("h*", md5(mt_rand())), 
                    0, 
                    $processedOpts[self::OPT_SALTSIZE]
                );
                $this->_log("createSecretKey(): salt=" . bin2hex($salt));
                
                /* Create key */
                $keysize = mcrypt_enc_get_key_size($td);
                $enc_key = mhash_keygen_s2k(
                    $processedOpts[self::OPT_HASH], 
                    $password, 
                    $salt, 
                    $keysize
                );

                /* Intialize encryption */
                mcrypt_generic_init($td, $enc_key, $iv);
                
                /* Encrypt data */
                $encrypted = bin2hex(mcrypt_generic($td, $key));
                $this->_log("createSecretKey(): key=$encrypted");
                
                // store the salt as the 1st 8 bytes
                $encrypted = bin2hex($iv) . bin2hex($salt) . $encrypted;
                
                /* Terminate encryption handler */
                mcrypt_generic_deinit($td);
                mcrypt_module_close($td);
            } else {
                $encrypted = bin2hex($key);
            }
            
            // store the key
            $algo = (isset($options[self::OPT_CIPHER]) ? 
                    $options[self::OPT_CIPHER] : 
                    self::$_symmetricOptions[self::OPT_CIPHER]);
            $this->_setSecretKeyEntry(
                $alias, 
                $encrypted, 
                $algo, 
                $size
            );
        }
        catch (Exception $e) {
            throw new Crypt_KeyStore_Exception($e);
        }
        
        return;
    }
    
    /**
     * Creates a new private key and certificate signing request (CSR) for the
     * private key. The CSR is returned for signing.
     * 
     * @param string $alias    alias to store new key/certificate under
     * @param string $password password used to encrypt key entry
     * @param array  $dn       distinguished name used to create CSR
     * @param array  $options  key pair/certificate generation options
     * 
     * @return string                                  
     */         
    public function createCSR($alias, $password=false, $dn=array(), 
        $options=array()
    ) {
    
        if (!isset($alias) || $alias == '') {
            throw new Crypt_KeyStore_Exception("Alias must be specified");
        }
        
        $processedOpts = $this->_processAsymmetricOptions($options);
        $size          = $processedOpts[self::OPT_KEYSIZE];
        
        $this->_log("Private key size: $size");
        
        try {
        
            $config  = array('digest_alg'       => 
                                $processedOpts[self::OPT_DIGEST],
                             'private_key_bits' => $size,
                             'private_key_type' => 
                                $processedOpts[self::OPT_KEYTYPE],
                             'encrypt_key'      => false);
            $pkey    = openssl_pkey_new(/*$config*/);
            $csr     = openssl_csr_new($dn, $pkey);
            if ($csr === false) {
                throw new Crypt_KeyStore_Exception('Failed to create CSR');
            }
            $csrtext = '';
            if (!openssl_csr_export($csr, $csrtext)) {
                throw new Crypt_KeyStore_Exception('Failed to export CSR');
            }
            
            // create a self-signed cert as a place-holder
            $sscert = openssl_csr_sign(
                $csr, 
                null, 
                $pkey, 
                $processedOpts[self::OPT_CERT_DAYS]
            );
            
            $pkeyOut = false;
            if ($password != false) {
                openssl_pkey_export($pkey, $pkeyOut, $password);
            } else {
                openssl_pkey_export($pkey, $pkeyOut);
            }
            
            $certOut = false;
            openssl_x509_export($sscert, $certOut, true);
            openssl_free_key($pkey);
            
            // add private key to key store
            $keyType = (isset($options[self::OPT_KEYTYPE]) ? 
                $options[self::OPT_KEYTYPE] : 
                self::$_asymmetricOptions[self::OPT_KEYTYPE]);
            $this->_setKeyEntry(
                $alias, 
                $pkeyOut, 
                $keyType,
                $size,
                $certOut, 
                array($certOut)
            );
        }
        catch (Crypt_KeyStore_Exception $e) {
            throw $e;
        }
        catch (Exception $e) {
            throw new Crypt_KeyStore_Exception($e);
        }
        
        return $csrtext;
    }
    
    /**
     * Imports a signed-certificate into the key store assigning the alias to
     * the new entry. If the alias is a pre-existing private key, the certificate
     * must be valid and correspond to the private key. Otherwise, an exception
     * is thrown.
     * 
     * @param string $cert     the certificate to import
     * @param string $alias    the alias of the entry to import certificate into
     * @param string $password private key password
     *      
     * @return void          
     */
    public function importCertificate($cert, $alias, $password=false) 
    {
        if ($this->containsAlias($alias)) {
            if ($this->isCertificateEntry($alias)) {
            
                // all right, what kind of entry is this, anyway?
                $entry = $this->getEntry($alias);
                switch ($entry->getEntryType()) {
                
                case Crypt_KeyStore_BaseEntry::PRIVATEKEY_TYPE:
                
                    // replacing existing public key cert with this cert - 
                    // check it's validity
                    $this->_log("Getting private key for alias $alias");
                    $privkey = $this->_getKey($alias, $password);
                    if ($privkey != null) {
                    
                        $isValid = openssl_x509_check_private_key($cert, $privkey);
                        openssl_free_key($privkey);
                        
                        if ($isValid) {
                            $chain    = $entry->getCertificateChain();
                            $chain[0] = $cert;
                            $this->_setKeyEntry(
                                $alias, 
                                $privkey, 
                                $entry->getPrivateKey()->getAlgorithm(),
                                $entry->getPrivateKey()->getSize(),
                                $cert, 
                                $chain
                            );
                        } else {
                            throw new Crypt_KeyStore_Exception(
                                    "Certificate does not match private key");
                        }
                    } else {
                        throw new Crypt_KeyStore_Exception("Failed to get "
                                . "private key");
                    }
                    break;
                    
                case Crypt_KeyStore_BaseEntry::TRUSTEDCERT_TYPE:
                
                    // replacing trusted cert with this c ert -
                    // just do it
                    $this->_setCertificateEntry($alias, $cert);
                    break;
                    
                default:
                
                    // shouldn't get here, but just in case
                    throw new Crypt_KeyStore_Exception(
                        "Alias $alias refers to an existing non-certificate entry");
                    break;
                }
            } else {
                // certificates can only be imported into certificate entries
                throw new Crypt_KeyStore_Exception(
                        "Alias $alias refers to an existing non-certificate entry");
            }
        } else {
            $this->_setEntry(
                $alias,
                new Crypt_KeyStore_TrustedCertificateEntry($cert)
            );
        }
        
        return;
    }
    
    /**
     * Encrypts the data with the key stored with the alias, optionally using
     * the password to decrypt the key.
     *      
     * @param string $data     the plain text data to encrypt
     * @param string $alias    the alias of the key to use to encrypt
     * @param string $password the password to use to decrypt the key
     * @param array  $options  array of encryption options
     *      
     * @return string the encrypted data                              
     */
    public function encrypt($data, $alias, $password=false, $options=array())
    {
        $encData = '';
        
        // lookup the key entry
        if ($this->containsAlias($alias)) {
            $entry = $this->_entries[$alias];
            switch ($entry->getEntryType()) {
            case Crypt_KeyStore_BaseEntry::PRIVATEKEY_TYPE:
                // asymmetric - use public key for encyption
                $encData = $this->_encryptAsymmetric(
                    $data, 
                    $alias, 
                    $password, 
                    $options
                );
                break;
            case Crypt_KeyStore_BaseEntry::SECRETKEY_TYPE:
                // symmetric - use secret key for encryption
                $encData = $this->_encryptSymmetric(
                    $data, 
                    $alias, 
                    $password, 
                    $options
                );
                break;
            default:
                // unsupported type for encryption
                throw new Crypt_KeyStore_Exception(
                    "Invalid key type for encryption"
                );
                break;
            }
        } else {
            throw new Crypt_KeyStore_Exception(
                    "Key for alias $alias is not in this Crypt_KeyStore");
        }
                
        return $encData;
    }         
    
    /**
     * Encrypts the data with the key store entry provided using asymmetric
     * encryption.
     *
     * @param string $data     the plain text data to encrypt
     * @param string $alias    the alias of the key to use
     * @param string $password the password to use to decrypt the key
     * @param array  $options  array of encryption options
     * 
     * @return string the encrypted data
     */                                       
    private function _encryptAsymmetric($data, $alias, $password, $options)
    {
        $encData = '';
        $entry   = $this->getEntry($alias);
        $pubKey  = $entry->getCertificate()->getPublicKey()->getEncoded();
        if ($pubKey != null) {
            if (!openssl_public_encrypt($data, $encData, $pubKey)) {
                throw new Crypt_KeyStore_Exception("Failed to encrypt with pub key");
            }
        } else {
            throw new Crypt_KeyStore_Exception("Failed to get pub key from cert");
        }
        
        return $encData;
    }
    
    /**
     * Encrypts the data with the key store entry provided using symmetric
     * encryption.
     *
     * @param string $data     the plain text data to encrypt
     * @param string $alias    the alias of the key to use
     * @param string $password the password to use to decrypt the key
     * @param array  $options  array of encryption options
     * 
     * @return string the encrypted data
     */                                       
    private function _encryptSymmetric($data, $alias, $password, $options)
    {
        $encData = '';
        $key     = null;
        
        $processedOpts = $this->_processSymmetricOptions($options);
        
        try {
            $key = $this->_getKey($alias, $password);
            
            /* Open the cipher */
            $td = mcrypt_module_open(
                $processedOpts[self::OPT_CIPHER], 
                '', 
                $processedOpts[self::OPT_MODE], 
                ''
            );
            
            /* create IV */
            $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
            
            /* Intialize encryption */
            mcrypt_generic_init($td, $key, $iv);
            
            /* Encrypt data */
            $encData = bin2hex($iv) . bin2hex(mcrypt_generic($td, $data));
    
            /* Terminate encryption handler */
            mcrypt_generic_deinit($td);
            mcrypt_module_close($td);
        } catch (Exception $e) {
            throw new Crypt_KeyStore_Exception($e);
        }
        
        return $encData;
    }
    
    /**
     * Decrypts the data with the key stored with the alias, optionally using
     * the password to decrypt the key.
     * 
     * @param string $encData  the encrypted data to decrypt
     * @param string $alias    the alias of the key to use to decrypt
     * @param string $password the password to use to decrypt the key
     * @param array  $options  array of decryption options
     * 
     * @return string the encrypted data                              
     */
    public function decrypt($encData, $alias, $password=false, $options=array())
    {
        $data = '';
        
        // lookup the key entry
        if ($this->containsAlias($alias)) {
            $entry = $this->_entries[$alias];
            switch ($entry->getEntryType()) {
            case Crypt_KeyStore_BaseEntry::PRIVATEKEY_TYPE:
                // asymmetric - use public key for encyption
                $data = $this->_decryptAsymmetric(
                    $encData, 
                    $alias, 
                    $password,
                    $options
                );
                break;
            case Crypt_KeyStore_BaseEntry::SECRETKEY_TYPE:
                // symmetric - use secret key for encryption
                $data = $this->_decryptSymmetric(
                    $encData, 
                    $alias, 
                    $password,
                    $options
                );
                break;
            default:
                // unsupported type for encryption
                throw new Crypt_KeyStore_Exception("Invalid entry type "
                        . "for decryption");
                break;
            }
        } else {
            throw new Crypt_KeyStore_Exception("Entry for alias $alias "
                    . "is not in this Crypt_KeyStore");
        }
        
        return $data;
    }
    
    /**
     * Decrypts the data with the key store entry provided using asymmetric
     * decryption.
     *
     * @param string $encData  the encrypted data to decrypt
     * @param string $alias    the alias of the key to use to decrypt
     * @param string $password the password to use to decrypt the key
     * @param array  $options  array of decryption options     
     * 
     * @return string the plain text data
     */                                       
    private function _decryptAsymmetric($encData, $alias, $password, $options)
    {
        $data = '';
    
        // use the private getKey method to retrieve decrypted private key
        $key = $this->_getKey($alias, $password);
        if ($key != null) {
            if (!openssl_private_decrypt($encData, $data, $key)) {
                throw new Crypt_KeyStoreException("Failed to decrypt "
                        . "with private key");
            }
            openssl_free_key($key);
        } else {
            throw new Crypt_KeyStore_Exception("Failed to get private key");
        }
        
        return $data;
    }
    
    /**
     * Decrypts the data with the key store entry provided using symmetric
     * decryption.
     *
     * @param string $encData  the encrypted data to decrypt
     * @param string $alias    the alias of the key to use to decrypt
     * @param string $password the password to use to decrypt the key
     * @param array  $options  array of decryption options     
     * 
     * @return string the plain text data
     */                                       
    private function _decryptSymmetric($encData, $alias, $password, $options)
    {
        $data = '';
        $key  = null;
        
        $processedOpts = $this->_processSymmetricOptions($options);
        try {
            $key = $this->_getKey($alias, $password);
            
            /* Open the cipher */
            $td = mcrypt_module_open(
                $processedOpts[self::OPT_CIPHER], 
                '', 
                $processedOpts[self::OPT_MODE], 
                ''
            );
            
            // get IV from beginning of encrypted string
            $ivsize = mcrypt_enc_get_iv_size($td);
            $iv     = pack(
                'H*', 
                substr(
                    $encData, 
                    0, 
                    $ivsize * 2
                )
            );
                            
            // calculate the header size and get encrypted data
            $header_size    = $ivsize * 2;
            $encoded_cipher = substr($encData, $header_size);
            $cipher         = pack('H*', $encoded_cipher);
            
            // Intialize encryption from the IV and dec_key
            mcrypt_generic_init($td, $key, $iv);
            
            // Decrypt encrypted string, trimming the result due to padding
            $data = trim(mdecrypt_generic($td, $cipher));
            
            // Terminate encryption handler
            mcrypt_generic_deinit($td);
            mcrypt_module_close($td);
        } catch (Exception $e) {
            throw new Crypt_KeyStore_Exception($e);
        }
        
        return $data;
    }
    
    /**
     * Signs the data with the private key stored by the specified alias and
     * returns the signature hex-encoded.
     * 
     * @param string $data     the data to be signed
     * @param string $alias    the alias of the private key to use for signing
     * @param string $password the password to unlock the private key
     * @param array  $options  array of signing options     
     * 
     * @return string the signature                              
     */         
    public function sign($data, $alias, $password=false, $options=array())
    {
        $ok        = 0;
        $signature = '';
        
        if ($this->isCertificateEntry($alias)) {
        
            $key = $this->_getKey($alias, $password);
            if ($key != null) {
                
                $processedOpts = $this->_processAsymmetricOptions($options);
                
                try {
                    
                    // compute signature
                    $ok = openssl_sign(
                        $data, 
                        $signature, 
                        $key, 
                        $processedOpts[self::OPT_DIGEST]
                    );
                    
                    // free the key from memory
                    openssl_free_key($key);
                }
                catch (Exception $e) {
                    throw new Crypt_KeyStore_Exception($e);
                }
            } else {
                throw new Crypt_KeyStore_Exception(
                        "Failed to get private key for entry $alias");
            }
        } else {
            throw new Crypt_KeyStore_Exception(
                    "Entry $alias is not a valid entry for signatures");
        }
        
        if ($ok == false) {
            throw new Crypt_KeyStore_Exception("Failed to create signature");
        }
        
        return bin2hex($signature);
    }
    
    /**
     * Verifies the signature was signed by the private key stored by the
     * specified alias. The signature must be the hex-encoded signature.
     * 
     * @param string $data      the original data to verify signature against     
     * @param string $signature the hex-encoded signature to verify
     * @param string $alias     the alias of the private key
     * @param array  $options   array of verifying options     
     * 
     * @return boolean true if signature is valid, false if not
     */         
    public function verify($data, $signature, $alias, $options=array())
    {
        $ok     = 0;
        $binSig = '';
        if ($this->isCertificateEntry($alias)) {
        
            $processedOpts = $this->_processAsymmetricOptions($options);
            $entry         = $this->getEntry($alias);
            switch ($entry->getEntryType()) {
            case Crypt_KeyStore_BaseEntry::PRIVATEKEY_TYPE:
                $cert = $entry->getCertificate()->getEncoded();
                break;
            case Crypt_KeyStore_BaseEntry::TRUSTEDCERT_TYPE:
                $cert = $entry->getTrustedCertificate()->getEncoded();
                break;
            default:
                throw new Crypt_KeyStore_Exception("Invalid entry "
                        . "type for signature");
                break;
            }
            
            try {
                $binSig = pack('H*', $signature);
                // compute signature
                $ok = openssl_verify(
                    $data, 
                    $binSig, 
                    $cert, 
                    $processedOpts[self::OPT_DIGEST]
                );
            }
            catch (Exception $e) {
                throw new Crypt_KeyStore_Exception($e);
            }
        } else {
            throw new Crypt_KeyStore_Exception(
                    "Entry $alias is not a valid entry for signatures");
        }
        
        if ($ok < 0) {
            throw new Crypt_KeyStore_Exception("Failed to verify signature");
        }
        
        return ($ok == 1);
    }
    
    /**
     * Loads this Crypt_KeyStore from the given input stream.
     *      
     * @param string $filename path and file name of key store file
     * @param string $password password used encrypt key store
     * @param array  $options  store options
     * 
     * @return void
     */
    public function load($filename, $password, $options=array()) 
    {
     
        try {
         
            // check that file exists
            if (!file_exists($filename)) {
                throw new Crypt_KeyStore_Exception("Key store does not exist"); 
            }
            
            // open read-only, put file pointer at beginning
            $fd = fopen($filename, 'r');
            if ($fd == false) {
                throw new Crypt_KeyStore_Exception("Failed to open key store"); 
            }
            
            $processedOpts = $this->_processSymmetricOptions($options);
            
            /* Open the cipher */
            $td = mcrypt_module_open(
                $processedOpts[self::OPT_CIPHER], 
                '', 
                $processedOpts[self::OPT_MODE], 
                ''
            );
            
            // get the IV and salt from beginning of file and decode from hex
            $ivsize = mcrypt_enc_get_iv_size($td);
            $iv     = pack(
                'H*', 
                fread($fd, $ivsize * 2)
            );
            $salt   = pack(
                'H*', 
                fread($fd, $processedOpts[self::OPT_SALTSIZE] * 2)
            );
            
            // create the decryption key from the password, salt, and keysize
            // the keysize is cipher dependent - see above
            $dec_key = mhash_keygen_s2k(
                $processedOpts[self::OPT_HASH], 
                $password, 
                $salt, 
                mcrypt_enc_get_key_size($td)
            );
                    
            /* Intialize encryption */
            mcrypt_generic_init($td, $dec_key, $iv);
            
            // read the entries from the remaining key store file
            // and explode them into an array, delimited by |
            $header_size = ($ivsize * 2) + 
                    ($processedOpts[self::OPT_SALTSIZE] * 2);
            $entries     = explode(
                '|', 
                fread($fd, filesize($filename) - $header_size)
            );
            foreach ($entries as $entry) {
             
                // we may have an empty array elem because of a trailing |
                if ($entry != '') {
                     
                    // explode the entries into a list of record data 
                    // delimited by ,
                    list($alias, $type, $size, $algo, $keysize, $encoded_data) 
                        = explode(',', $entry);
                    
                    // decode the encrypted key data, and then decrypt it
                    $data = mdecrypt_generic($td, pack('H*', $encoded_data));
                     
                    // depending on the key type, add the 
                    // specific key to the key store
                    switch ($type) {
                     
                    // asymmetric key entry
                    case Crypt_KeyStore_BaseEntry::PRIVATEKEY_TYPE:
                        // the asymmetric key is split into sections of 
                        // PEM formatted ascii-armored texts - after they are 
                        // decrypted, we can list them delimited by ,
                        $sections = explode(',', $data);
                        if (is_array($sections) && count($sections) > 1) {
                            
                            $pkey  = $sections[0];
                            $cert  = $sections[1];
                            $chain = array();
                            
                            if (count($sections) > 2) {
                            
                                // if the sections is built out of more than 2 
                                // sections, the assumption is that there is a 
                                // chain file - copy the certs from public chain 
                                // file
                                for ($n = 2; $n < count($sections); $n++) {
                                    $chain[] = $sections[$n];
                                }
                            } else {
                            
                                // otherwise, just use the public cert as 
                                // the chain
                                $chain[] = $sections[1];
                            }
                            
                            $this->_setKeyEntry(
                                $alias, 
                                $pkey, 
                                $algo,
                                $keysize,
                                $cert, 
                                $chain
                            );
                        } else {
                            $this->_log(
                                "Invalid asymmetric entry format", 
                                PEAR_LOG_WARNING
                            );
                        }
                        break;
                
                    // symmetric key entry
                    case Crypt_KeyStore_BaseEntry::SECRETKEY_TYPE:
                    
                        // there is only one portion the the scecret key - 
                        // the key itself
                        // this is easy
                        $this->_setSecretKeyEntry($alias, $data, $algo, $keysize);
                        break;
                        
                    // trusted certificate entry
                    case Crypt_KeyStore_BaseEntry::TRUSTEDCERT_TYPE:
                    
                        // a trusted certificate
                        $this->_setCertificateEntry($alias, $data);
                        break;
                        
                    // wtf? ignore
                    default:
                        $this->_log(
                            "Invalid key store entry type: $type", 
                            PEAR_LOG_WARNING
                        );
                        break;
                    }
                }
            }
             
            /* Terminate encryption handler */
            mcrypt_generic_deinit($td);
            mcrypt_module_close($td);
            
            fclose($fd);
        }
        catch (Crypt_KeyStore_Exception $e) {
            throw $e;
        }
        catch (Exception $e) {
            // general exception handler
            throw new Crypt_KeyStore_Exception($e);
        }
        
        return;
    }
    
    /**
     * Stores this Crypt_KeyStore to the given output stream, and protects its 
     * integrity with the given password.
     *      
     * @param string $filename path and file name of key store file
     * @param string $password password used encrypt key store
     * @param array  $options  store options
     * 
     * @return void
     */
    public function store($filename, $password, $options=array()) 
    {
    
        try {
            
            // open the file in write mode, truncate any existing file, and go to
            // the beginning
            $fd = fopen($filename, 'w');
            if ($fd == false) {
                throw new Crypt_KeyStore_Exception("Failed to open key store"); 
            }             
            
            $processedOpts = $this->_processSymmetricOptions($options);
        
            /* Open the cipher */
            $td = mcrypt_module_open(
                $processedOpts[self::OPT_CIPHER], 
                '', 
                $processedOpts[self::OPT_MODE], 
                ''
            );
        
            // Create the IV and determine the keysize length, use MCRYPT_RAND
            // on Windows instead
            $iv   = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
            $salt = substr(
                pack('H*', md5(mt_rand())), 
                0, 
                $processedOpts[self::OPT_SALTSIZE]
            );
            
            /* Create key */
            $enc_key = mhash_keygen_s2k(
                $processedOpts[self::OPT_HASH], 
                $password, 
                $salt, 
                mcrypt_enc_get_key_size($td)
            );
                
            /* Intialize encryption */
            mcrypt_generic_init($td, $enc_key, $iv);
            
            // the file contents will have 16 bytes of data - the IV and the 
            // key salt so we can decrypt the file later
            fwrite($fd, bin2hex($iv));
            fwrite($fd, bin2hex($salt));
            
            foreach ($this->_entries as $alias => $entry) {
            
                // each entry is stored as:
                // |alias,type,encrypted_size_in_bytes,key algorithm,
                // keysize,hex-encoded encrypted_data|
                $strEntry  = "" . $entry;
                $entryType = $entry->getEntryType();
                fwrite($fd, "|");
                fwrite($fd, $alias);
                fwrite($fd, ",");
                fwrite($fd, $entryType);
                fwrite($fd, ",");
                fwrite($fd, count($strEntry));
                fwrite($fd, ",");
                
                switch ($entryType) {
                case Crypt_KeyStore_BaseEntry::PRIVATEKEY_TYPE:
                    $algo    = $entry->getPrivateKey()->getAlgorithm();
                    $keysize = $entry->getPrivateKey()->getSize();
                    break;
                case Crypt_KeyStore_BaseEntry::SECRETKEY_TYPE:
                    $algo    = $entry->getSecretKey()->getAlgorithm();
                    $keysize = $entry->getSecretKey()->getSize();
                    break;
                case Crypt_KeyStore_BaseEntry::TRUSTEDCERT_TYPE:
                    $algo    = '';
                    $keysize = 0;
                    break;
                }
                fwrite($fd, $algo);
                fwrite($fd, ",");
                fwrite($fd, $keysize);
                fwrite($fd, ",");
                
                fwrite($fd, bin2hex(mcrypt_generic($td, $strEntry)));
                fwrite($fd, "|");
            }
            
            /* Terminate encryption handler */
            mcrypt_generic_deinit($td);
            mcrypt_module_close($td);
            
            // close file desc
            fclose($fd);
        }
        catch (Crypt_KeyStore_Exception $e) {
            throw $e;
        }
        catch (Exception $e) {
            // general exception handler
            throw new Crypt_KeyStore_Exception($e);
        }
        
        return;
    }
}

?>
