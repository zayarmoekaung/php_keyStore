**

## PHP KeyStore

This is the copy of Crypt_KeyStore Library developed by [ne0phyte](https://web.archive.org/web/20170607151254/http://ne0phyte.com/ "ne0phyte")
The following are from the original home page now on wayback machine - 
https://web.archive.org/web/20170607151254/http://phpkeystore.org/


**Basic Examples**

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


**Contact**

-   Steve Wamsley  [swamsley@gmail.com](https://web.archive.org/web/20170607151254/mailto:swamsley@gmail.com)

**
