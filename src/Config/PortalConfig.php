<?php

declare(strict_types=1);

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2019, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace LC\Portal\Config;

use DateInterval;
use LC\Portal\Config\Exception\ConfigException;

class PortalConfig extends Config
{
    public function getStyleName(): ?string
    {
        return $this->optionalString('styleName');
    }

    public function getSecureCookie(): bool
    {
        if (null === $configValue = $this->optionalBool('secureCookie')) {
            return false;
        }

        return $configValue;
    }

    public function getAuthMethod(): string
    {
        if (null === $configValue = $this->optionalString('authMethod')) {
            return 'DbAuthentication';
        }

        return $configValue;
    }

    public function getSessionExpiry(): DateInterval
    {
        if (null === $configValue = $this->optionalString('sessionExpiry')) {
            return new DateInterval('P90D');
        }

        return new DateInterval($configValue);
    }

    /**
     * @return array<string>
     */
    public function getAdminPermissionList(): array
    {
        if (null === $configValue = $this->optionalStringArray('adminPermissionList')) {
            return [];
        }

        return $configValue;
    }

    /**
     * @return array<string>
     */
    public function getAdminUserIdList(): array
    {
        if (null === $configValue = $this->optionalStringArray('adminUserIdList')) {
            return [];
        }

        return $configValue;
    }

    /**
     * @return array<string,string>
     */
    public function getSupportedLanguages(): array
    {
        if (null === $configValue = $this->optionalStringStringArray('supportedLanguages')) {
            return ['en_US' => 'English'];
        }

        return $configValue;
    }

    public function getSamlAuthenticationConfig(): SamlAuthenticationConfig
    {
        if (!\array_key_exists('SamlAuthentication', $this->configData)) {
            throw new ConfigException('key "SamlAuthentication" is missing');
        }

        return new SamlAuthenticationConfig($this->configData['SamlAuthentication']);
    }

    public function getLdapAuthenticationConfig(): LdapAuthenticationConfig
    {
        if (!\array_key_exists('LdapAuthentication', $this->configData)) {
            throw new ConfigException('key "LdapAuthentication" is missing');
        }

        return new LdapAuthenticationConfig($this->configData['LdapAuthentication']);
    }

    public function getRadiusAuthenticationConfig(): RadiusAuthenticationConfig
    {
        if (!\array_key_exists('RadiusAuthentication', $this->configData)) {
            throw new ConfigException('key "RadiusAuthentication" is missing');
        }

        return new RadiusAuthenticationConfig($this->configData['RadiusAuthentication']);
    }

    public function getEnableApi(): bool
    {
        if (null === $configValue = $this->optionalBool('enableApi')) {
            return true;
        }

        return $configValue;
    }

    public function getApiConfig(): ApiConfig
    {
        $apiConfigData = [];
        if (\array_key_exists('Api', $this->configData)) {
            $apiConfigData = $this->configData['Api'];
        }

        return new ApiConfig($apiConfigData);
    }

    public function getProfileConfig(string $profileId): ProfileConfig
    {
        $profileConfigList = $this->getProfileConfigList();
        if (!\array_key_exists($profileId, $profileConfigList)) {
            // XXX better error
            throw new ConfigException('XXX');
        }

        return $profileConfigList[$profileId];
    }

    /**
     * @return array<string,ProfileConfig>
     */
    public function getProfileConfigList(): array
    {
        // XXX make sure we have no callers that would be btter of with the
        // getProfileConfig($profileId) call!
        if (!\array_key_exists('ProfileList', $this->configData)) {
            return [];
        }

        if (!\is_array($this->configData['ProfileList'])) {
            // XXX
            throw new ConfigException('');
        }

        $profileConfigList = [];
        foreach ($this->configData['ProfileList'] as $profileId => $profileConfigData) {
            // XXX make sure profileId = string
            // XXX make sure profileConfigData = array
            $profileConfigList[$profileId] = new ProfileConfig($profileConfigData);
        }

        return $profileConfigList;
    }
}
