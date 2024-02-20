***Crypt_PHPKeyStore***
This is the copy of the crypt_keyStore developed by  ne0phyte , I saved this on this repo to preserve the codes.The home page used to be a website called phpkeystore.org which is now 
unaccessable, but you may find it in this wayback machine link - https://web.archive.org/web/20170607151254/http://phpkeystore.org/.
The Following are from its original home page.

Basic Examples

<?php
    require_once 'Crypt/KeyStore.php';
    
    // get the key store instance
    $ks = Crypt_KeyStore::getInstance('DefaultKeyStore');

    // create a secret (symmetric) key
    $ks->createSecretKey('mykey', 'changeit');

    // encrypt some data
    $data = 'The quick brown fox jumped over the fence';
    $cipher = $ks->encrypt($data, 'mykey', 'changeit');

    // decrypt some data
    $decrypted = $ks->decrypt($cipher, 'mykey', 'changeit');

    // save the key store
    $ks->store('mykeystore.pks', 'changeit');

    // load a keystore file
    $ks->load('mykeystore.pks', 'changeit');

    // delete a key
    $ks->deleteEntry('mykey');

    // and so-on
?>
Contact

Steve Wamsley swamsley@gmail.com
