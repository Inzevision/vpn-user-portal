<?php

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2019, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace LC\Portal\CA;

use DateTime;
use DateTimeInterface;
use LC\Portal\FileIO;
use phpseclib\Crypt\RSA;
use phpseclib\File\X509;

class PhpSecLibCa implements CaInterface
{
    const KEY_SIZE = 2048;

    /** @var string */
    private $caDir;

    public function __construct(string $caDir)
    {
        $this->caDir = $caDir;
    }

    public function init(): void
    {
        $caKeyFile = sprintf('%s/ca.key', $this->caDir);
        $caCertFile = sprintf('%s/ca.crt', $this->caDir);

        if (FileIO::exists($caKeyFile)) {
            // CA exists, no init required
            return;
        }

        // generate CA key/cert
        $privateKey = new RSA();
        $keyInfo = $privateKey->createKey(self::KEY_SIZE);
        $privateKey->loadKey($keyInfo['privatekey']);

        $publicKey = new RSA();
        $publicKey->loadKey($keyInfo['publickey']);
        $publicKey->setPublicKey();

        $certSubject = new X509();
        $certSubject->setDNProp('CN', 'VPN CA');
        $certSubject->setPublicKey($publicKey);

        $certIssuer = new X509();
        $certIssuer->setPrivateKey($privateKey);
        $certIssuer->setDN($certSubject->getDN());

        $caSigner = new X509();
        $caSigner->makeCA();
        $signedCa = $caSigner->sign($certIssuer, $certSubject, 'sha256WithRSAEncryption');
        $caCert = $caSigner->saveX509($signedCa);

        FileIO::writeFile($caKeyFile, $keyInfo['privatekey']);
        FileIO::writeFile($caCertFile, $caCert);
    }

    public function caCert(): string
    {
        return FileIO::readFile(sprintf('%s/ca.crt', $this->caDir));
    }

    public function serverCert(string $commonName): CertInfo
    {
        $privateKey = new RSA();
        $keyInfo = $privateKey->createKey(self::KEY_SIZE);
        $publicKey = new RSA();
        $publicKey->loadKey($keyInfo['publickey']);
        $publicKey->setPublicKey();

        $certSubject = new X509();
        $certSubject->setDNProp('CN', $commonName);
        $certSubject->setPublicKey($publicKey);

        // CA
        $caPrivateKey = new RSA();
        $caPrivateKey->loadKey(FileIO::readFile(sprintf('%s/ca.key', $this->caDir)));

        $certIssuer = new X509();
        $certIssuer->setDNProp('CN', 'VPN CA');
        $certIssuer->setPrivateKey($caPrivateKey);
        $certIssuer->setEndDate('2020-02-02 02:02:02');
        $signedCert = $certIssuer->sign($certIssuer, $certSubject, 'sha256WithRSAEncryption');
        $clientCert = $certIssuer->saveX509($signedCert);

        return new CertInfo(
            $clientCert,
            $keyInfo['privatekey'],
            new DateTime(),
            new DateTime('2020-02-02 02:02:02')
        );
    }

    public function clientCert(string $commonName, DateTimeInterface $expiresAt): CertInfo
    {
    }
}
