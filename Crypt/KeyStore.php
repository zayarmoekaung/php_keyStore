<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * The PHP Key Store Library.
 *  
 * The KeyStore class encapsulates the key management and usage functionality that
 * is used to create asymmetric or symmetric encryption keys and then uses
 * those keys for cryptographic functionality (encrypt, decrypt, sign, verify). 
 * The class is designed to be used as a self-contained, self-maintained key store.
 * Keys are created by the key store and stored in the key store for the life time 
 * of keys. When a key is used for encryption/decryption, it is used in the key 
 * store itself. The key is never exported in plaintext from the KeyStore or used for
 * encryption/decryption outside of the key store.
 *  
 * PHP version 5
 *
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   SVN: $Id: KeyStore.php 6677 2009-11-30 18:05:15Z swamsley $
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */

/**
 * 
 */
require_once './KeyStore/Exception.php';
require_once './KeyStore/SPI/KeyStoreSPI.php';

/**
 * <p>This class represents a storage facility for cryptographic keys and
 * certificates.</p>
 *  
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   Release: 0.1.9dev
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */
class Crypt_KeyStore
{

    public static $DEFAULT_Crypt_KeyStore_TYPE = 'PKS';
    
    /**
     * The SPI implementation instance.
     */
    private $_spi = null;
    
    /**
     * Constructs a key store for the service provider interface implementation. 
     * This constructor is private and should only be called by the 
     * ::getInstance(...) method.
     * 
     * @param Crypt_KeyStore_SPI_KeyStoreSPI $spi service provider implementation
     */
    private function __construct($spi) 
    {
        $this->_spi = $spi;
    }
    
    /** 
     * Returns a Crypt_KeyStore object of the specified type. If an instance of the
     * specified type is not already initialized, a new instance is created.     
     * 
     * @param string $type the type of key store instance
     * 
     * @return Crypt_KeyStore 
     */
    public static function getInstance($type) 
    {
        $instance = null;
        
        @include_once "./KeyStore/SPI/{$type}.php";
        $clazz = "Crypt_KeyStore_SPI_{$type}";
        
        if (!class_exists($clazz)) {
            throw new Crypt_KeyStore_Exception(
                    "$type has no installed/configured implementation");
        }
        
        $spi = new $clazz;
        if (!($spi instanceof Crypt_KeyStore_SPI_KeyStoreSPI)) {
            throw new Crypt_KeyStore_Exception(
                    "Invalid key store implementation: $clazz");
        }
        
        $instance = new Crypt_KeyStore($spi);

        return $instance;
    }
    
    /**
     * Returns the default Crypt_KeyStore type.
     * 
     * @return string the default key store type
     */
    public static function getDefaultType() 
    {
        return Crypt_KeyStore::$DEFAULT_Crypt_KeyStore_TYPE;
    }
    
    /**
     * Lists all the alias names of this Crypt_KeyStore.
     * 
     * @return array<string> array of alias strings
     */
    public function aliases() 
    {
        return $this->_spi->aliases();
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
        return $this->_spi->containsAlias($alias);
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
        $this->_spi->deleteEntry($alias);
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
        return $this->_spi->entryInstanceOf($alias, $entryClazzName);
    }
    
    /**
     * Returns the (alias) name of the first Crypt_KeyStore entry whose certificate 
     * matches the given certificate.
     *      
     * @param string $cert the certificate text
     *      
     * @return string the alias of the certificate
     */
    public function getCertificateAlias($cert)
    {
        return $this->_spi->getCertificateAlias($cert);
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
        return $this->_spi->getCertificateChain($alias);
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
        return $this->_spi->getCreationDate($alias);
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
    public function getEntry($alias, $options=array()) 
    {
        return $this->_spi->getEntry($alias, $options);
    }
    
    /**
     * Returns the type of this Crypt_KeyStore.
     *      
     * @return string the type of key store implementation
     */
    public function getType() 
    {
         return $this->_spi->getType();
    }
    
    /**
     * Returns true if the entry identified by the given alias was created by 
     * a call to _setCertificateEntry, or created by a call to _setEntry with a 
     * Crypt_KeyStore_TrustedCertificateEntry.
     *      
     * @param string $alias the alias of the entry to test
     *      
     * @return boolean true if entry is a certificate, false if not
     */
    public function isCertificateEntry($alias) 
    {
        return $this->_spi->isCertificateEntry($alias);
    }
    
    /**
     * Returns true if the entry identified by the given alias was created by a 
     * call to _setKeyEntry, or created by a call to _setEntry with a 
     * Crypt_KeyStore_PrivateKeyEntry or a Crypt_KeyStore_SecretKeyEntry.
     *      
     * @param string $alias the alias of the entry to test
     *      
     * @return boolean true if entry is a key, false if not
     */
    public function isKeyEntry($alias) 
    {
        return $this->_spi->isKeyEntry($alias);
    }
    
    /**
     * Retrieves the number of entries in this Crypt_KeyStore.
     *      
     * @return int the number of entries in the Crypt_KeyStore instance
     */
    public function size() 
    {
        return $this->_spi->size();
    }
    
    /**
     * Creates a symmetric secret key from a randomly generated
     * pass phrase and stores the new key in the key store, protecting it with
     * the password if specified. The pass phrase is a sequence of random hex
     * numbers which is then used to generate the key using a
     * SHA-256 hash and 8-bytes of salt.
     *      
     * @param string $alias    the alias the new key will be stored as
     * @param array  $password password used to protected the key
     * @param array  $options  array of key creation options
     * 
     * @return void          
     */
    public function createSecretKey($alias, $password=false, $options=array()) 
    {
        $this->_spi->createSecretKey($alias, $password, $options);
        return;
    }
    
    /**
     * Helper function to return an associative array initialized with default
     * values for a distinguished name (DN) worthy of creating a CSR.
     * TODO - populate with values from a configuration file
     *      
     * @return array<string, string> associative array of DN values          
     */
    public function initializeDn() 
    {
        $dn = array("countryName" => "US",
            "stateOrProvinceName" => "MO",
            "localityName" => "St. Louis",
            "organizationName" => "Katana",
            "organizationalUnitName" => "Development",
            "commonName" => "ne0phyte.com",
            "emailAddress" => "swamsley@gmail.com");
            
        return $dn;
    }
    
    /**
     * Creates a new private key and certificate signing request (CSR) for the
     * private key. The CSR is returned for signing.
     * 
     * @param string $alias    alias to store new key/certificate under
     * @param string $password password used to protect the private key
     * @param array  $dn       distinguished name used to create CSR
     * @param array  $options  array of key pair/certificate creation options
     * 
     * @return string                                  
     */         
    public function createCSR($alias,
        $password=false,
        $dn=array(),
        $options=array()
    ) {
        return $this->_spi->createCSR($alias, $password, $dn, $options);
    }
    
    /**
     * Imports a signed-certificate into the key store assigning the alias to
     * the new entry. If the alias is a pre-existing private key, the certificate
     * must be valid and correspond to the private key. Otherwise, an exception
     * is thrown. If no entry exists for the alias, a new trusted certificate
     * entry is created for the certificate.     
     * 
     * @param string $cert     the certificate to import
     * @param string $alias    the alias of the entry to import certificate into
     * @param string $password private key password
     * 
     * @return void          
     */
    public function importCertificate($cert, $alias, $password=false) 
    {
        $this->_spi->importCertificate($cert, $alias, $password);
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
        return $this->_spi->encrypt($data, $alias, $password, $options);
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
        return $this->_spi->decrypt($encData, $alias, $password, $options);
    }
    
    /**
     * Signs the data with the private key stored by the specified alias.
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
        return $this->_spi->sign($data, $alias, $password, $options);
    }
    
    /**
     * Verifies the signature was signed by the private key stored by the
     * specified alias.
     * 
     * @param string $data      the original data to verify signature against     
     * @param string $signature the signature to verify
     * @param string $alias     the alias of the private key
     * @param array  $options   array of verification options
     * 
     * @return boolean true if signature is valid, false if not
     */         
    public function verify($data, $signature, $alias, $options=array())
    {
        return $this->_spi->verify($data, $signature, $alias, $options);
    }
    
    /**
     * Loads this Crypt_KeyStore from the given input stream.
     *      
     * @param string $filename path and file name of key store file
     * @param string $password password used encrypt key store
     * @param array  $options  load options
     * 
     * @return void
     */
    public function load($filename, $password, $options=array()) 
    {
        $this->_spi->load($filename, $password, $options);
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
        $this->_spi->store($filename, $password, $options);
        return;
    }
}
?>
