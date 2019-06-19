<?php

declare(strict_types=1);

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2019, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

require_once dirname(__DIR__).'/vendor/autoload.php';
$baseDir = dirname(__DIR__);

use fkooman\Jwt\Keys\EdDSA\SecretKey;
use fkooman\OAuth\Server\OAuthServer;
use fkooman\SeCookie\Cookie;
use fkooman\SeCookie\Session;
use LC\OpenVpn\ManagementSocket;
use LC\Portal\CA\EasyRsaCa;
use LC\Portal\Config\PortalConfig;
use LC\Portal\FileIO;
use LC\Portal\Http\AdminHook;
use LC\Portal\Http\AdminPortalModule;
use LC\Portal\Http\CsrfProtectionHook;
use LC\Portal\Http\DisabledUserHook;
use LC\Portal\Http\FormAuthenticationHook;
use LC\Portal\Http\FormAuthenticationModule;
use LC\Portal\Http\HtmlResponse;
use LC\Portal\Http\InputValidation;
use LC\Portal\Http\LanguageSwitcherHook;
use LC\Portal\Http\LdapAuth;
use LC\Portal\Http\LogoutModule;
use LC\Portal\Http\OAuthModule;
use LC\Portal\Http\PasswdModule;
use LC\Portal\Http\RadiusAuth;
use LC\Portal\Http\Request;
use LC\Portal\Http\SamlModule;
use LC\Portal\Http\Service;
use LC\Portal\Http\UpdateSessionInfoHook;
use LC\Portal\Http\VpnPortalModule;
use LC\Portal\Init;
use LC\Portal\LdapClient;
use LC\Portal\Logger;
use LC\Portal\OAuth\ClientDb;
use LC\Portal\OAuth\PublicSigner;
use LC\Portal\OpenVpn\ServerManager;
use LC\Portal\OpenVpn\TlsCrypt;
use LC\Portal\Storage;
use LC\Portal\Tpl;

$logger = new Logger('vpn-user-portal');

try {
    $request = new Request($_SERVER, $_GET, $_POST);

    $dataDir = sprintf('%s/data', $baseDir);
    $configDir = sprintf('%s/config', $baseDir);

    $init = new Init($baseDir);
    $init->init();

    $portalConfig = PortalConfig::fromFile(sprintf('%s/config.php', $configDir));

    $templateDirs = [
        sprintf('%s/views', $baseDir),
        sprintf('%s/views', $configDir),
    ];

    if (null !== $styleName = $portalConfig->getStyleName()) {
        $templateDirs[] = sprintf('%s/views/%s', $baseDir, $styleName);
    }

    $sessionExpiry = $portalConfig->getSessionExpiry();

    // we always want browser session to expiry after PT8H hours, *EXCEPT* when
    // the configured "sessionExpiry" is < PT8H, then we want to follow that
    // setting...
    $browserSessionExpiry = 'PT8H';
    $dateTime = new DateTime();
    if (date_add(clone $dateTime, new DateInterval($browserSessionExpiry)) > date_add(clone $dateTime, $sessionExpiry)) {
        $browserSessionExpiry = $sessionExpiry;
    }

    $secureCookie = $portalConfig->getSecureCookie();

    $cookie = new Cookie(
        [
            'SameSite' => 'Lax',
            'Secure' => $secureCookie,
            'Max-Age' => 60 * 60 * 24 * 90,   // 90 days
        ]
    );

    $session = new Session(
        [
            'SessionName' => 'SID',
            'DomainBinding' => $request->getServerName(),
            'PathBinding' => $request->getRoot(),
            'SessionExpiry' => $browserSessionExpiry,
        ],
        new Cookie(
            [
                // we need to bind to "Path", otherwise the (Basic)
                // authentication mechanism will set a cookie for
                // {ROOT}/_form/auth/
                'Path' => $request->getRoot(),
                // we can't set "SameSite" to Lax if we want to support the
                // SAML HTTP-POST binding...
                'SameSite' => null,
                'Secure' => $secureCookie,
            ]
        )
    );

    $supportedLanguages = $portalConfig->getSupportedLanguages();
    // the first listed language is the default language
    $uiLang = array_keys($supportedLanguages)[0];
    $languageFile = null;
    if (array_key_exists('ui_lang', $_COOKIE)) {
        $uiLang = InputValidation::uiLang($_COOKIE['ui_lang']);
    }
    if ('en_US' !== $uiLang) {
        if (array_key_exists($uiLang, $supportedLanguages)) {
            $languageFile = sprintf('%s/locale/%s.php', $baseDir, $uiLang);
        }
    }

    $tpl = new Tpl($templateDirs, $languageFile);
    $tpl->addDefault(
        [
            'requestRoot' => $request->getRoot(),
        ]
    );
    $tpl->addDefault(
        [
            'supportedLanguages' => $supportedLanguages,
        ]
    );

    $service = new Service($tpl);
    $service->addBeforeHook('csrf_protection', new CsrfProtectionHook());
    $service->addBeforeHook('language_switcher', new LanguageSwitcherHook(array_keys($supportedLanguages), $cookie));

    // Authentication
    $authMethod = $portalConfig->getAuthMethod();

    $logoutUrl = null;
    $returnParameter = 'ReturnTo';
    if ('SamlAuthentication' === $authMethod) {
        $logoutUrl = $request->getRootUri().'_saml/logout';
    }

    $storage = new Storage(
        new PDO(sprintf('sqlite://%s/db.sqlite', $dataDir)),
        sprintf('%s/schema', $baseDir)
    );

    $service->addModule(new LogoutModule($session, $logoutUrl, $returnParameter));
    switch ($authMethod) {
        case 'DbAuthentication':
            $service->addBeforeHook(
                'auth',
                new FormAuthenticationHook(
                    $session,
                    $tpl
                )
            );

            $service->addModule(
                new FormAuthenticationModule(
                    $storage,
                    $session,
                    $tpl
                )
            );
            // add module for changing password
            $service->addModule(
                new PasswdModule(
                    $tpl,
                    $storage
                )
            );

            break;
        case 'SamlAuthentication':
            $samlModule = new SamlModule(
                $portalConfig->getSamlAuthenticationConfig()
            );
            $service->addBeforeHook('auth', $samlModule);
            $service->addModule($samlModule);

            break;
        case 'LdapAuthentication':
            $ldapAuthenticationConfig = $portalConfig->getLdapAuthenticationConfig();
            $service->addBeforeHook(
                'auth',
                new FormAuthenticationHook(
                    $session,
                    $tpl
                )
            );
            $ldapClient = new LdapClient(
                $ldapAuthenticationConfig->getLdapUri()
            );
            $userAuth = new LdapAuth(
                $logger,
                $ldapClient,
                $ldapAuthenticationConfig->getBindDnTemplate(),
                $ldapAuthenticationConfig->getBaseDn(),
                $ldapAuthenticationConfig->getUserFilterTemplate(),
                $ldapAuthenticationConfig->getPermissionAttributeList()
            );
            $service->addModule(
                new FormAuthenticationModule(
                    $userAuth,
                    $session,
                    $tpl
                )
            );

            break;
        case 'RadiusAuthentication':
            $radiusAuthenticationConfig = $portalConfig->getRadiusAuthenticationConfig();
            $service->addBeforeHook(
                'auth',
                new FormAuthenticationHook(
                    $session,
                    $tpl
                )
            );
            $userAuth = new RadiusAuth(
                $logger,
                $radiusAuthenticationConfig
            );
            $service->addModule(
                new FormAuthenticationModule(
                    $userAuth,
                    $session,
                    $tpl
                )
            );

            break;
        default:
            throw new RuntimeException('unsupported authentication mechanism');
    }

    $tpl->addDefault(
        [
            'authMethod' => $authMethod,
        ]
    );

    $service->addBeforeHook('disabled_user', new DisabledUserHook($storage));
    $service->addBeforeHook('update_session_info', new UpdateSessionInfoHook($storage, $session, $sessionExpiry));

    // isAdmin
    $service->addBeforeHook(
        'is_admin',
        new AdminHook(
            $portalConfig->getAdminPermissionList(),
            $portalConfig->getAdminUserIdList(),
            $tpl
        )
    );

    $easyRsaDir = sprintf('%s/easy-rsa', $baseDir);
    $easyRsaDataDir = sprintf('%s/easy-rsa', $dataDir);
    $easyRsaCa = new EasyRsaCa(
        $easyRsaDir,
        $easyRsaDataDir
    );
    $tlsCrypt = TlsCrypt::fromFile(sprintf('%s/tls-crypt.key', $dataDir));
    $serverManager = new ServerManager($portalConfig, new ManagementSocket());
    $serverManager->setLogger($logger);
    $clientDb = new clientDb();

    // portal module
    $vpnPortalModule = new VpnPortalModule(
        $portalConfig,
        $tpl,
        $session,
        $storage,
        $easyRsaCa,
        $tlsCrypt,
        $serverManager,
        $clientDb
    );
    $service->addModule($vpnPortalModule);

    // admin module
    $adminPortalModule = new AdminPortalModule(
        $dataDir,
        $portalConfig,
        $tpl,
        $storage,
        $serverManager
    );
    $service->addModule($adminPortalModule);

    if (false !== $portalConfig->getEnableApi()) {
        $apiConfig = $portalConfig->getApiConfig();

        // OAuth module
        $secretKey = SecretKey::fromEncodedString(
            FileIO::readFile(
                sprintf('%s/oauth.key', $dataDir)
            )
        );

        $oauthServer = new OAuthServer(
            $storage,
            $clientDb,
            new PublicSigner($secretKey->getPublicKey(), $secretKey)
        );
        $oauthServer->setAccessTokenExpiry($apiConfig->getTokenExpiry());
        $oauthModule = new OAuthModule(
            $tpl,
            $oauthServer
        );
        $service->addModule($oauthModule);
    }

    $service->run($request)->send();
} catch (Exception $e) {
    $logger->error($e->getMessage());
    $response = new HtmlResponse($e->getMessage(), 500);
    $response->send();
}
