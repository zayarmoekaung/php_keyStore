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
 * @version   SVN: $Id: KeyTool.php 6677 2009-11-30 18:05:15Z swamsley $
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */

/**
 *
 */ 
require_once 'Crypt/KeyStore.php';
require_once 'Console/Getopt.php';

if (!defined('CRYPT_KEYSTORE_MAIN_METHOD')) {
    define('CRYPT_KEYSTORE_MAIN_METHOD', 'Crypt_KeyStore_KeyTool::main');
}

define('CRYPT_KEYSTORE_CMD_CERTREQ', 'certreq');
define('CRYPT_KEYSTORE_CMD_DELETE', 'delete');
define('CRYPT_KEYSTORE_CMD_EXPORT', 'export');
define('CRYPT_KEYSTORE_CMD_GENKEY', 'genkey');
define('CRYPT_KEYSTORE_CMD_IMPORT', 'import');
define('CRYPT_KEYSTORE_CMD_KEYCLONE', 'keyclone');
define('CRYPT_KEYSTORE_CMD_KEYPASSWD', 'keypasswd');
define('CRYPT_KEYSTORE_CMD_LIST', 'list');
define('CRYPT_KEYSTORE_CMD_STOREPASSWD', 'storepasswd');

define('CRYPT_KEYSTORE_CMDOPT_ALIAS', 'alias');
define('CRYPT_KEYSTORE_CMDOPT_FILE', 'file');
define('CRYPT_KEYSTORE_CMDOPT_KEYPASS', 'keypass');
define('CRYPT_KEYSTORE_CMDOPT_KEYSTORE', 'Crypt_KeyStore');
define('CRYPT_KEYSTORE_CMDOPT_STOREPASS', 'storepass');
define('CRYPT_KEYSTORE_CMDOPT_DEST', 'dest');
define('CRYPT_KEYSTORE_CMDOPT_NEW', 'new');

/**
 * A trusted certificate key store entry that includes a trusted certificate.
 *  
 * @category  Encryption
 * @package   Crypt_KeyStore
 * @author    Steve Wamsley <swamsley@gmail.com>
 * @copyright 2008 Katanaa
 * @license   http://www.gnu.org/copyleft/lesser.html  LGPL License 2.1
 * @version   Release: 0.1.9dev
 * @link      http://phpkeystore.org/Crypt_KeyStore
 */ 
class Crypt_KeyStore_KeyTool
{
    private static $_cmds = array(CRYPT_KEYSTORE_CMD_CERTREQ => 'doCertReq',
            CRYPT_KEYSTORE_CMD_DELETE => 'doDelete',
            CRYPT_KEYSTORE_CMD_EXPORT => 'doExport',
            CRYPT_KEYSTORE_CMD_GENKEY => 'doGenKey',
            CRYPT_KEYSTORE_CMD_IMPORT => 'doImport',
            CRYPT_KEYSTORE_CMD_KEYCLONE => 'doKeyClone',
            CRYPT_KEYSTORE_CMD_KEYPASSWD => 'doKeyPasswd',
            CRYPT_KEYSTORE_CMD_LIST => 'doList',
            CRYPT_KEYSTORE_CMD_STOREPASSWD => 'doStorePasswd');
            
    private static $_cmdopts = array(CRYPT_KEYSTORE_CMDOPT_ALIAS,
            CRYPT_KEYSTORE_CMDOPT_FILE,
            CRYPT_KEYSTORE_CMDOPT_KEYPASS,
            CRYPT_KEYSTORE_CMDOPT_KEYSTORE,
            CRYPT_KEYSTORE_CMDOPT_STOREPASS,
            CRYPT_KEYSTORE_CMDOPT_DEST,
            CRYPT_KEYSTORE_CMDOPT_NEW);

    /**
     * Program entry point.
     * 
     * @return void
     */                   
    public static function main()
    {
        echo "PHPKeyTool by Steve Wamsley <swamsley@gmail.com> "
                . "Copyright 2008 Katanaa\n\n";
        
        $arguments = self::handleArguments();
        $func      = self::$_cmds[$arguments['command']];
        self::$func($arguments);
        
        exit(0);
        
        return;
    }
    
    /**
     * Process certreq command.
     *         
     * @param array $args command line arguments
     * 
     * @return void          
     */         
    protected static function doCertReq($args) 
    {
        echo "KeyTool::doCertReq()\n";
    }
    
    /**
     * Process delete command.
     *         
     * @param array $args command line arguments
     * 
     * @return void          
     */         
    protected static function doDelete($args) 
    {
        echo "KeyTool::doDelete()\n";
    }
    
    /**
     * Process export command.
     *         
     * @param array $args command line arguments
     * 
     * @return void          
     */         
    protected static function doExport($args) 
    {
        echo "KeyTool::doExport()\n";
    }
    
    /**
     * Process genkey command.
     *         
     * @param array $args command line arguments
     * 
     * @return void          
     */         
    protected static function doGenKey($args) 
    {
        echo "KeyTool::doGenKey()\n";
        print_r($args);
        $ks = Crypt_KeyStore::getInstance('DefaultKeyStore');
        $ks->createSecretKey(
            $args['alias'],
            (isset($args['keypass']) ? $args['keypass'] : false)
        );
        $ks->store($args['Crypt_KeyStore'], $args['storepass']);
        return;
    }
    
    /**
     * Process import command.
     * 
     * @param array $args command line arguments
     * 
     * @return void          
     */         
    protected static function doImport($args) 
    {
        echo "KeyTool::doImport()\n";
    }
    
    /**
     * Process keyclone command.
     *         
     * @param array $args command line arguments
     * 
     * @return void          
     */         
    protected static function doKeyClone($args) 
    {
        echo "KeyTool::doKeyClone()\n";
    }
    
    /**
     * Process keypasswd command.
     *         
     * @param array $args command line arguments
     * 
     * @return void          
     */         
    protected static function doKeyPasswd($args) 
    {
        echo "KeyTool::doKeyPassd()\n";
    }
    
    /**
     * Process list command.
     *         
     * @param array $args command line arguments
     * 
     * @return void          
     */         
    protected static function doList($args) 
    {
        echo "KeyTool::doList()\n";
        $ks = Crypt_KeyStore::getInstance('DefaultKeyStore');
        $ks->load($args['Crypt_KeyStore'], $args['storepass']);
        $aliases = $ks->aliases();
        foreach ($aliases as $alias) {
            echo $alias . "\n";
        }
        return;
    }
    
    /**
     * Process storepasswd command.
     *         
     * @param array $args command line arguments
     * 
     * @return void          
     */         
    protected static function doStorePasswd($args) 
    {
        echo "KeyTool::doStorePasswd()\n";
    }
    
    /**
     * Parses command line into command line arguments array.
     *          
     * @return array
     */         
    protected static function handleArguments()
    {
        $arguments = array();
        
        $shortopts = 'v::h::';
        $longopts  = array('certreq',
            'delete',
            'export',
            'genkey',
            'help',
            'import',
            'keyclone',
            'list',
            'alias==',
            'file==',
            'keypass==',
            'Crypt_KeyStore==',
            'storepass==',
            'dest==',
            'new==');
        
        try {
            $con  = new Console_Getopt;
            $args = $con->readPHPArgv();
            array_shift($args);
            $options = $con->getopt2($args, $shortopts, $longopts);
            
            if (!is_array($options)) {
                echo "Failed to parse command line arguments:\n";
                echo $options;
                exit(1);
            }
            
            if (count($options[0]) == 0 
                || self::hasOption('--help', $options)
                || self::hasOption('h', $options)
            ) {
                self::showHelp();
                exit(1);
            }
        }
        catch (RuntimeException $e) {
            echo "Failed to parse command line arguments:\n";
            echo $e->getMessage() . "\n";
            exit(1);
        }
        
        foreach (self::$_cmds as $cmd => $cmdFunc) {
            if (self::hasOption("--" . $cmd, $options)) {
                $arguments['command'] = $cmd;
                break;
            }
        }
        
        foreach (self::$_cmdopts as $cmdopt) {
            if (self::hasOption("--" . $cmdopt, $options)) {
                $arguments[$cmdopt] = self::getOptionValue("--" . $cmdopt, $options);
            }
        }
        
        return $arguments;
    }
    
    /**
     * Determines whether the named option is specified in the options array.
     * 
     * @param string $optName name of option
     * @param array  $options array of command line options
     * 
     * @return boolean                         
     */         
    public static function hasOption($optName, $options)
    {
        $result = false;
        foreach ($options[0] as $opt) {
            if ($opt[0] == $optName) {
                $result = true;
                break;
            }
        }
        
        return $result;
    }
    
    /**
     * Returns the named option's value from the options array.
     * 
     * @param string $optName name of option
     * @param array  $options array of command line options
     * 
     * @return string
     */
    public static function getOptionValue($optName, $options)
    {
        $optValue = null;
        foreach ($options[0] as $opt) {
            if ($opt[0] == $optName) {
                $optValue = $opt[1];
                break;
            }
        }
        
        return $optValue;
    }
    
    /**
     * Displays the help message.
     * 
     * @return void
     */
    public static function showHelp()
    {
        echo "Usage: phpkeytool [switches]\n";
        
        echo "
--certreq     [-v] --alias <alias>
              --file <csr_file> [--keypass <keypass>]
              --Crypt_KeyStore <Crypt_KeyStore> --storepass <storepass>

--delete      [-v] --alias <alias>
              --Crypt_KeyStore <Crypt_KeyStore> --storepass <storepass>

--export      [-v] --alias <alias> --file <cert_file>
              --Crypt_KeyStore <Crypt_KeyStore> --storepass <storepass>

--genkey      [-v] --alias <alias>
              [--keypass <keypass>]
              --Crypt_KeyStore <Crypt_KeyStore> --storepass <storepass>

--help

--import      [-v] --alias <alias>
              --file <cert_file> [--keypass <keypass>]
              --Crypt_KeyStore <Crypt_KeyStore> --storepass <storepass>

--keyclone    [-v] --alias <alias> --dest <dest_alias>
              --keypass <keypass> --new <new_keypass>
              --Crypt_KeyStore <Crypt_KeyStore> --storepass <storepass>

--keypasswd   [-v] --alias <alias>
              --keypass <old_keypass> --new <new_keypass>
              --Crypt_KeyStore <Crypt_KeyStore> --storepass <storepass>

--list        [-v] [--alias <alias>]
              --Crypt_KeyStore <Crypt_KeyStore> --storepass <storepass>

--storepasswd [-v] --new <new_storepass>
              --Crypt_KeyStore <Crypt_KeyStore> --storepass <storepass>";
              
        return;
    }
}

if (CRYPT_KEYSTORE_MAIN_METHOD == 'Crypt_KeyStore_KeyTool::main') {
    Crypt_KeyStore_KeyTool::main();
}

?>
