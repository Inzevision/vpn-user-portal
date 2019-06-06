<?php

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2019, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace LC\Portal\CA;

use DateTime;
use fyrkat\openssl\CSR;
use fyrkat\openssl\DN;
use fyrkat\openssl\OpenSSLConfig;
use fyrkat\openssl\PrivateKey;
use fyrkat\openssl\X509;
use LC\Portal\FileIO;

class FyrkatOpenSslCa implements CaInterface
{
    /** @var string */
    private $caDir;

    /** @var \fyrkat\openssl\OpenSSLConfig */
    private $keyConfig;

    /** @var \fyrkat\openssl\OpenSSLConfig */
    private $caConfig;

    /** @var \fyrkat\openssl\OpenSSLConfig */
    private $serverConfig;

    /** @var \fyrkat\openssl\OpenSSLConfig */
    private $clientConfig;

    /**
     * @param string $caDir
     */
    public function __construct($caDir)
    {
        $this->caDir = $caDir;
        $this->keyConfig = new OpenSSLConfig(OpenSSLConfig::KEY_EC);
        $this->caConfig = new OpenSSLConfig(OpenSSLConfig::X509_CA);
        $this->serverConfig = new OpenSSLConfig(OpenSSLConfig::X509_SERVER);
        $this->clientConfig = new OpenSSLConfig(OpenSSLConfig::X509_CLIENT);
    }

    /**
     * @return void
     */
    public function init()
    {
        $privateKey = new PrivateKey($this->keyConfig);
        $caCsr = CSR::generate(
            new DN(
                [
                    'CN' => 'VPN CA',
                ]
            ),
            $privateKey,
            $this->caConfig
        );

        $caCert = $caCsr->sign(null, $privateKey, 3650, $this->caConfig);
        $caKeyPem = '';
        $privateKey->export($caKeyPem, null, $this->keyConfig);
        FileIO::writeFile(sprintf('%s/ca.crt', $this->caDir), (string) $caCert);
        FileIO::writeFile(sprintf('%s/ca.key', $this->caDir), (string) $caKeyPem, 0600);
    }

    /**
     * @return string
     */
    public function caCert()
    {
        return FileIO::readFile(sprintf('%s/ca.crt', $this->caDir));
    }

    /**
     * @param string $commonName
     *
     * @return array{cert:string, key:string, valid_from:int, valid_to:int}
     */
    public function serverCert($commonName)
    {
        $caPrivateKey = new PrivateKey(FileIO::readFile(sprintf('%s/ca.key', $this->caDir)));
        $caCert = new X509(FileIO::readFile(sprintf('%s/ca.crt', $this->caDir)));

        $serverKey = new PrivateKey($this->keyConfig);
        $serverCsr = CSR::generate(
            new DN(
                [
                    'CN' => $commonName,
                ]
            ),
            $serverKey
        );

        $serverCert = $serverCsr->sign($caCert, $caPrivateKey, 365, $this->serverConfig);
        $serverKeyPem = '';
        $serverKey->export($serverKeyPem, null, $this->keyConfig);

        return [
            'cert' => (string) $serverCert,
            'key' => $serverKeyPem,
            'valid_from' => 0, // XXX
            'valid_to' => 0, // XXX
        ];
    }

    /**
     * @param string    $commonName
     * @param \DateTime $expiresAt
     *
     * @return array{cert:string, key:string, valid_from:int, valid_to:int}
     */
    public function clientCert($commonName, DateTime $expiresAt)
    {
        $caPrivateKey = new PrivateKey(FileIO::readFile(sprintf('%s/ca.key', $this->caDir)));
        $caCert = new X509(FileIO::readFile(sprintf('%s/ca.crt', $this->caDir)));

        $clientKey = new PrivateKey($this->keyConfig);
        $clientCsr = CSR::generate(
            new DN(
                [
                    'CN' => $commonName,
                ]
            ),
            $clientKey
        );

        $clientCert = $clientCsr->sign($caCert, $caPrivateKey, 365, $this->clientConfig);
        $clientKeyPem = '';
        $clientKey->export($clientKeyPem, null, $this->keyConfig);

        return [
            'cert' => (string) $clientCert,
            'key' => $clientKeyPem,
            'valid_from' => 0, // XXX
            'valid_to' => 0, // XXX
        ];
    }
}
