<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Service provider interface (SPI).
 * 
 * Interface to be implemented by Crypt_KeyStore providers.
 *  
 * PHP version 5
 *
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   SVN: $Id: KeyStoreSPI.php 6677 2009-11-30 18:05:15Z swamsley $
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */ 
 
/**
 * This class defines the Service Provider Interface (SPI) for the KeyStore 
 * class. All the abstract methods in this class must be implemented by each 
 * cryptographic service provider who wishes to supply the implementation of a 
 * keystore for a particular keystore type.
 *  
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   Release: 0.1.9dev
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */ 
interface Crypt_KeyStore_SPI_KeyStoreSPI
{
    /**
     * Lists all the alias names of this Crypt_KeyStore.
     * 
     * @return array<string> array of alias strings
     */
    public function aliases();
    
    /**
     * Checks if the given alias exists in this Crypt_KeyStore.
     *      
     * @param string $alias the alias of the entry to query
     *      
     * @return boolean true if the key store contains an entry with the alias,
     *      false if not     
     */
    public function containsAlias($alias);
    
    /**
     * Deletes the entry identified by the given alias from this Crypt_KeyStore.
     *      
     * @param string $alias the alias of the entry to delete
     * 
     * @return void          
     */
    public function deleteEntry($alias);
    
    /**
     * Determines if the Crypt_KeyStore Entry for the specified alias is an 
     * instance or subclass of the specified entryClass.
     *      
     * @param string $alias          the alias of the entry to test
     * @param class  $entryClazzName the key store entry class name to test
     *      
     * @return boolean true if entry is instance of the class name, false if not
     */
    public function entryInstanceOf($alias, $entryClazzName);
    
    /**
     * Returns the (alias) name of the first Crypt_KeyStore entry whose certificate 
     * matches the given certificate.
     *      
     * @param string $cert the certificate text
     *      
     * @return string the alias of the certificate
     */
    public function getCertificateAlias($cert);
    
    /**
     * Returns the certificate chain associated with the given alias.
     *      
     * @param string $alias the alias of the certificate chain
     *      
     * @return array an array of certificates in the chain, or NULL if the 
     *         chain does not exist for the the alias     
     */
    public function getCertificateChain($alias);
    
    /** 
     * Returns the creation date of the entry identified by the given alias.
     *      
     * @param string $alias the alias of the entry to retrieve
     *      
     * @return DateTime the date/time the key was added to the key store
     */
    public function getCreationDate($alias);
    
    /** 
     * Gets a Crypt_KeyStore Entry for the specified alias with the specified 
     * protection parameter.
     *      
     * @param string $alias   the alias of the entry to retrieve
     * @param array  $options the password used to decrypt the key
     *      
     * @return Crypt_KeyStore_Entry 
     */
    public function getEntry($alias, $options=false);
        
    /**
     * Returns the type of this Crypt_KeyStore.
     *      
     * @return string the type of key store implementation
     */
    public function getType();
    
    /**
     * Returns true if the entry identified by the given alias was created by 
     * a call to _setCertificateEntry, or created by a call to _setEntry with a 
     * Crypt_KeyStore_TrustedCertificateEntry.
     *      
     * @param string $alias the alias of the entry to test
     *      
     * @return boolean true if entry is a certificate, false if not
     */
    public function isCertificateEntry($alias);
    
    /**
     * Returns true if the entry identified by the given alias was created by a 
     * call to _setKeyEntry, or created by a call to _setEntry with a 
     * Crypt_KeyStore_PrivateKeyEntry or a Crypt_KeyStore_SecretKeyEntry.
     *      
     * @param string $alias the alias of the entry to test
     *      
     * @return boolean true if entry is a key, false if not
     */
    public function isKeyEntry($alias);
    
    /**
     * Retrieves the number of entries in this Crypt_KeyStore.
     *      
     * @return int the number of entries in the Crypt_KeyStore instance
     */
    public function size();
    
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
    public function createSecretKey($alias, $password=false, $options=array());
    
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
    );
    
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
    public function importCertificate($cert, $alias, $password=false);
    
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
    public function encrypt($data, $alias, $password=false, $options=array());
    
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
    public function decrypt($encData, $alias, $password=false, $options=array());
    
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
    public function sign($data, $alias, $password=false, $options=array());
    
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
    public function verify($data, $signature, $alias, $options=array());
    
    /**
     * Loads this Crypt_KeyStore from the given input stream.
     *      
     * @param string $filename path and file name of key store file
     * @param string $password password used encrypt key store
     * @param array  $options  load options
     * 
     * @return void
     */
    public function load($filename, $password, $options=array());
    
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
    public function store($filename, $password, $options=array());
}
?>
