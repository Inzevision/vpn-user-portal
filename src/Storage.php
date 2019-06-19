<?php

declare(strict_types=1);

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2019, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace LC\Portal;

use DateTime;
use DateTimeInterface;
use fkooman\OAuth\Server\StorageInterface;
use fkooman\SqliteMigrate\Migration;
use LC\Portal\Http\CredentialValidatorInterface;
use LC\Portal\Http\UserInfo;
use PDO;

class Storage implements CredentialValidatorInterface, StorageInterface
{
    const CURRENT_SCHEMA_VERSION = '2019061901';

    /** @var \PDO */
    private $db;

    /** @var \DateTimeInterface */
    private $dateTime;

    /** @var \fkooman\SqliteMigrate\Migration */
    private $migration;

    public function __construct(PDO $db, string $schemaDir)
    {
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        if ('sqlite' === $db->getAttribute(PDO::ATTR_DRIVER_NAME)) {
            $db->exec('PRAGMA foreign_keys = ON');
        }
        $this->db = $db;
        $this->migration = new Migration($db, $schemaDir, self::CURRENT_SCHEMA_VERSION);
        $this->dateTime = new DateTime();
    }

    public function setDateTime(DateTimeInterface $dateTime): void
    {
        $this->dateTime = $dateTime;
    }

    public function getPdo(): PDO
    {
        return $this->db;
    }

    /**
     * @return false|UserInfo
     */
    public function isValid(string $authUser, string $authPass)
    {
        $stmt = $this->db->prepare(
            'SELECT
                password_hash
             FROM pdo_users
             WHERE
                user_id = :user_id'
        );

        $stmt->bindValue(':user_id', $authUser, PDO::PARAM_STR);
        $stmt->execute();
        if(false === $dbHash = $stmt->fetchColumn(0)) {
            // user not found
            return false;
        }
        $isVerified = password_verify($authPass, $dbHash);
        if ($isVerified) {
            return new UserInfo($authUser, []);
        }

        return false;
    }

    public function add(string $userId, string $userPass): void
    {
        if ($this->userExists($userId)) {
            $this->updatePassword($userId, $userPass);

            return;
        }

        $stmt = $this->db->prepare(
            'INSERT INTO
                pdo_users (user_id, password_hash, created_at)
            VALUES
                (:user_id, :password_hash, :created_at)'
        );

        $passwordHash = password_hash($userPass, PASSWORD_DEFAULT);
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->bindValue(':password_hash', $passwordHash, PDO::PARAM_STR);
        $stmt->bindValue(':created_at', $this->dateTime->format(DateTime::ATOM), PDO::PARAM_STR);
        $stmt->execute();
    }

    public function userExists(string $authUser): bool
    {
        $stmt = $this->db->prepare(
            'SELECT
                COUNT(*)
             FROM pdo_users
             WHERE
                user_id = :user_id'
        );

        $stmt->bindValue(':user_id', $authUser, PDO::PARAM_STR);
        $stmt->execute();

        return 1 === (int) $stmt->fetchColumn();
    }

    public function updatePassword(string $userId, string $newUserPass): bool
    {
        $stmt = $this->db->prepare(
            'UPDATE
                pdo_users
             SET
                password_hash = :password_hash
             WHERE
                user_id = :user_id'
        );

        $passwordHash = password_hash($newUserPass, PASSWORD_DEFAULT);
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->bindValue(':password_hash', $passwordHash, PDO::PARAM_STR);
        $stmt->execute();

        return 1 === $stmt->rowCount();
    }

    /**
     * @param string $authKey
     *
     * @return bool
     */
    public function hasAuthorization($authKey)
    {
        $stmt = $this->db->prepare(
            'SELECT
                user_id
             FROM authorizations
             WHERE
                auth_key = :auth_key'
        );

        $stmt->bindValue(':auth_key', $authKey, PDO::PARAM_STR);
        $stmt->execute();

        $userId = $stmt->fetchColumn();
        if (!\is_string($userId)) {
            return false;
        }

        $expiresAt = new DateTime($this->getSessionExpiresAt($userId));

        return $expiresAt > $this->dateTime;
    }

    /**
     * @param string $userId
     * @param string $clientId
     * @param string $scope
     * @param string $authKey
     *
     * @return void
     */
    public function storeAuthorization($userId, $clientId, $scope, $authKey)
    {
        // the "authorizations" table has the UNIQUE constraint on the
        // "auth_key" column, thus preventing multiple entries with the same
        // "auth_key" to make absolutely sure "auth_keys" cannot be replayed
        $stmt = $this->db->prepare(
            'INSERT INTO authorizations (
                auth_key,
                user_id,
                client_id,
                scope,
                auth_time
             ) 
             VALUES(
                :auth_key,
                :user_id, 
                :client_id,
                :scope,
                :auth_time
             )'
        );

        $stmt->bindValue(':auth_key', $authKey, PDO::PARAM_STR);
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->bindValue(':client_id', $clientId, PDO::PARAM_STR);
        $stmt->bindValue(':scope', $scope, PDO::PARAM_STR);
        $stmt->bindValue(':auth_time', $this->dateTime->format(DateTime::ATOM), PDO::PARAM_STR);
        $stmt->execute();
    }

    /**
     * @param string $userId
     *
     * @return array<array>
     */
    public function getAuthorizations($userId)
    {
        $stmt = $this->db->prepare(
            'SELECT
                auth_key,
                client_id,
                scope,
                auth_time
             FROM authorizations
             WHERE
                user_id = :user_id'
        );

        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * @param string $authKey
     *
     * @return void
     */
    public function deleteAuthorization($authKey)
    {
        $stmt = $this->db->prepare(
            'DELETE FROM
                authorizations
             WHERE
                auth_key = :auth_key'
        );

        $stmt->bindValue(':auth_key', $authKey, PDO::PARAM_STR);
        $stmt->execute();
    }

    public function getUsers(): array
    {
        $stmt = $this->db->prepare(
<<< 'SQL'
    SELECT
        user_id,
        session_expires_at,
        permission_list, 
        is_disabled
    FROM 
        users
SQL
        );
        $stmt->execute();

        $userList = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $userList[] = [
                'user_id' => $row['user_id'],
                'is_disabled' => (bool) $row['is_disabled'],
                'session_expires_at' => $row['session_expires_at'],
                'permission_list' => Json::decode($row['permission_list']),
            ];
        }

        return $userList;
    }

    /**
     * XXX why can this return null?
     */
    public function getSessionExpiresAt(string $userId): ?string
    {
        $this->addUser($userId);
        $stmt = $this->db->prepare(
<<< 'SQL'
    SELECT
        session_expires_at
    FROM 
        users
    WHERE 
        user_id = :user_id
SQL
        );
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->execute();

        return $stmt->fetchColumn();
    }

    /**
     * @return array<string>
     */
    public function getPermissionList(string $userId): array
    {
        $this->addUser($userId);
        $stmt = $this->db->prepare(
<<< 'SQL'
    SELECT
        permission_list
    FROM 
        users
    WHERE
        user_id = :user_id
SQL
        );
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->execute();

        return Json::decode($stmt->fetchColumn());
    }

    /**
     * XXX turn this into an object!
     *
     * @return false|array{user_id:string, user_is_disabled:bool, display_name:string, valid_from:string, valid_to:string, client_id: null|string}
     */
    public function getUserCertificateInfo(string $commonName)
    {
        $stmt = $this->db->prepare(
<<< 'SQL'
    SELECT 
        u.user_id AS user_id, 
        u.is_disabled AS user_is_disabled,
        c.display_name AS display_name,
        c.valid_from,
        c.valid_to,
        c.client_id
    FROM 
        users u, certificates c 
    WHERE 
        u.user_id = c.user_id AND 
        c.common_name = :common_name
SQL
        );

        $stmt->bindValue(':common_name', $commonName, PDO::PARAM_STR);
        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    /**
     * @param array<string> $permissionList
     */
    public function updateSessionInfo(string $userId, DateTimeInterface $sessionExpiresAt, array $permissionList): void
    {
        $this->addUser($userId);
        $stmt = $this->db->prepare(
<<< 'SQL'
    UPDATE
        users
    SET
        session_expires_at = :session_expires_at,
        permission_list = :permission_list
    WHERE
        user_id = :user_id
SQL
        );
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->bindValue(':session_expires_at', $sessionExpiresAt->format(DateTime::ATOM), PDO::PARAM_STR);
        $stmt->bindValue(':permission_list', Json::encode($permissionList), PDO::PARAM_STR);

        $stmt->execute();
    }

    public function addCertificate(string $userId, string $commonName, string $displayName, DateTimeInterface $validFrom, DateTimeInterface $validTo, ?string $clientId): void
    {
        $this->addUser($userId);
        $stmt = $this->db->prepare(
<<< 'SQL'
    INSERT INTO certificates 
        (common_name, user_id, display_name, valid_from, valid_to, client_id)
    VALUES
        (:common_name, :user_id, :display_name, :valid_from, :valid_to, :client_id)
SQL
        );
        $stmt->bindValue(':common_name', $commonName, PDO::PARAM_STR);
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->bindValue(':display_name', $displayName, PDO::PARAM_STR);
        $stmt->bindValue(':valid_from', $validFrom->format(DateTime::ATOM), PDO::PARAM_STR);
        $stmt->bindValue(':valid_to', $validTo->format(DateTime::ATOM), PDO::PARAM_STR);
        $stmt->bindValue(':client_id', $clientId, PDO::PARAM_STR | PDO::PARAM_NULL);
        $stmt->execute();
    }

    public function getCertificates(string $userId): array
    {
        $this->addUser($userId);
        $stmt = $this->db->prepare(
<<< 'SQL'
    SELECT
        common_name, 
        display_name, 
        valid_from, 
        valid_to,
        client_id
    FROM 
        certificates
    WHERE 
        user_id = :user_id
    ORDER BY
        valid_from DESC
SQL
        );
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function deleteCertificate(string $commonName): void
    {
        $stmt = $this->db->prepare(
<<< 'SQL'
    DELETE FROM 
        certificates 
    WHERE 
        common_name = :common_name
SQL
        );
        $stmt->bindValue(':common_name', $commonName, PDO::PARAM_STR);
        $stmt->execute();
    }

    public function deleteCertificatesOfClientId(string $userId, string $clientId): void
    {
        $stmt = $this->db->prepare(
<<< 'SQL'
    DELETE FROM 
        certificates 
    WHERE 
        user_id = :user_id 
    AND 
        client_id = :client_id
SQL
        );
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->bindValue(':client_id', $clientId, PDO::PARAM_STR);
        $stmt->execute();
    }

    public function disableUser(string $userId): void
    {
        $this->addUser($userId);
        $stmt = $this->db->prepare(
<<< 'SQL'
    UPDATE
        users 
    SET 
        is_disabled = 1 
    WHERE 
        user_id = :user_id
SQL
        );
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->execute();
    }

    public function enableUser(string $userId): void
    {
        $this->addUser($userId);
        $stmt = $this->db->prepare(
<<< 'SQL'
    UPDATE
        users 
    SET 
        is_disabled = 0 
    WHERE 
        user_id = :user_id
SQL
        );
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->execute();
    }

    public function isDisabledUser(string $userId): bool
    {
        $this->addUser($userId);
        $stmt = $this->db->prepare(
<<< 'SQL'
    SELECT
        is_disabled
    FROM 
        users
    WHERE 
        user_id = :user_id 
SQL
        );
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->execute();

        // because the user always exists, this will always return something,
        // this is why we don't need to distinguish between a successful fetch
        // or not, a bit ugly!
        return (bool) $stmt->fetchColumn();
    }

    public function clientConnect(string $profileId, string $commonName, string $ip4, string $ip6, DateTimeInterface $connectedAt): void
    {
        // update "lost" client entries when a new client connects that gets
        // the IP address of an existing entry that was not "closed" yet. This
        // may occur when the OpenVPN process dies without writing the
        // disconnect event to the log. We fix this when a new client
        // wants to connect and gets this exact same IP address...
        $stmt = $this->db->prepare(
<<< 'SQL'
        UPDATE 
            connection_log
        SET
            disconnected_at = :date_time,
            client_lost = 1
        WHERE
            profile_id = :profile_id
        AND
            ip4 = :ip4 
        AND
            ip6 = :ip6 
        AND
            disconnected_at IS NULL
SQL
        );

        $stmt->bindValue(':date_time', $connectedAt->format(DateTime::ATOM), PDO::PARAM_STR);
        $stmt->bindValue(':profile_id', $profileId, PDO::PARAM_STR);
        $stmt->bindValue(':ip4', $ip4, PDO::PARAM_STR);
        $stmt->bindValue(':ip6', $ip6, PDO::PARAM_STR);
        $stmt->execute();

        // this query is so complex, because we want to store the user_id in the
        // log as well, not just the common_name... the user may delete the
        // certificate, or the user account may be deleted...
        $stmt = $this->db->prepare(
<<< 'SQL'
    INSERT INTO connection_log 
        (
            user_id,
            profile_id,
            common_name,
            ip4,
            ip6,
            connected_at
        ) 
    VALUES
        (
            (
                SELECT
                    u.user_id
                FROM 
                    users u, certificates c
                WHERE
                    u.user_id = c.user_id
                AND
                    c.common_name = :common_name
            ),                
            :profile_id, 
            :common_name,
            :ip4,
            :ip6,
            :connected_at
        )
SQL
        );

        $stmt->bindValue(':profile_id', $profileId, PDO::PARAM_STR);
        $stmt->bindValue(':common_name', $commonName, PDO::PARAM_STR);
        $stmt->bindValue(':ip4', $ip4, PDO::PARAM_STR);
        $stmt->bindValue(':ip6', $ip6, PDO::PARAM_STR);
        $stmt->bindValue(':connected_at', $connectedAt->format(DateTime::ATOM), PDO::PARAM_STR);
        $stmt->execute();
    }

    public function clientDisconnect(string $profileId, string $commonName, string $ip4, string $ip6, DateTimeInterface $connectedAt, DateTimeInterface $disconnectedAt, int $bytesTransferred): void
    {
        $stmt = $this->db->prepare(
<<< 'SQL'
    UPDATE 
        connection_log
    SET 
        disconnected_at = :disconnected_at, 
        bytes_transferred = :bytes_transferred
    WHERE 
        profile_id = :profile_id 
    AND
        common_name = :common_name 
    AND
        ip4 = :ip4 
    AND
        ip6 = :ip6 
    AND
        connected_at = :connected_at
SQL
        );

        $stmt->bindValue(':profile_id', $profileId, PDO::PARAM_STR);
        $stmt->bindValue(':common_name', $commonName, PDO::PARAM_STR);
        $stmt->bindValue(':ip4', $ip4, PDO::PARAM_STR);
        $stmt->bindValue(':ip6', $ip6, PDO::PARAM_STR);
        $stmt->bindValue(':connected_at', $connectedAt->format(DateTime::ATOM), PDO::PARAM_STR);
        $stmt->bindValue(':disconnected_at', $disconnectedAt->format(DateTime::ATOM), PDO::PARAM_STR);
        $stmt->bindValue(':bytes_transferred', $bytesTransferred, PDO::PARAM_INT);
        $stmt->execute();
    }

    /**
     * @return false|array
     */
    public function getLogEntry(DateTimeInterface $dateTime, string $ipAddress)
    {
        $stmt = $this->db->prepare(
<<< 'SQL'
    SELECT 
        user_id,
        profile_id, 
        common_name, 
        ip4, 
        ip6, 
        connected_at, 
        disconnected_at,
        client_lost
    FROM
        connection_log
    WHERE
        (ip4 = :ip_address OR ip6 = :ip_address)
    AND 
        connected_at < :date_time
    AND 
        (disconnected_at > :date_time OR disconnected_at IS NULL)
SQL
        );
        $stmt->bindValue(':ip_address', $ipAddress, PDO::PARAM_STR);
        $stmt->bindValue(':date_time', $dateTime->format(DateTime::ATOM), PDO::PARAM_STR);
        $stmt->execute();

        // XXX can this also contain multiple results? I don't think so, but
        // make sure!
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function cleanConnectionLog(DateTimeInterface $dateTime): void
    {
        $stmt = $this->db->prepare(
<<< 'SQL'
    DELETE FROM
        connection_log
    WHERE
        connected_at < :date_time
    AND
        disconnected_at IS NOT NULL
SQL
        );

        $stmt->bindValue(':date_time', $dateTime->format(DateTime::ATOM), PDO::PARAM_STR);

        $stmt->execute();
    }

    public function cleanUserMessages(DateTimeInterface $dateTime): void
    {
        $stmt = $this->db->prepare(
<<< 'SQL'
    DELETE FROM
        user_messages
    WHERE
        date_time < :date_time
SQL
        );

        $stmt->bindValue(':date_time', $dateTime->format(DateTime::ATOM), PDO::PARAM_STR);

        $stmt->execute();
    }

    public function systemMessages(string $type): array
    {
        $stmt = $this->db->prepare(
<<< 'SQL'
    SELECT
        id, message, date_time 
    FROM 
        system_messages
    WHERE
        type = :type
SQL
        );

        $stmt->bindValue(':type', $type, PDO::PARAM_STR);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function addSystemMessage(string $type, string $message): void
    {
        $stmt = $this->db->prepare(
<<< 'SQL'
    INSERT INTO system_messages 
        (type, message, date_time) 
    VALUES
        (:type, :message, :date_time)
SQL
        );

        $stmt->bindValue(':type', $type, PDO::PARAM_STR);
        $stmt->bindValue(':message', $message, PDO::PARAM_STR);
        $stmt->bindValue(':date_time', $this->dateTime->format(DateTime::ATOM), PDO::PARAM_STR);
        $stmt->execute();
    }

    public function deleteSystemMessage(int $messageId): void
    {
        $stmt = $this->db->prepare(
<<< 'SQL'
    DELETE FROM 
        system_messages
    WHERE id = :message_id
SQL
        );

        $stmt->bindValue(':message_id', $messageId, PDO::PARAM_INT);
        $stmt->execute();
    }

    public function userMessages(string $userId): array
    {
        $this->addUser($userId);
        $stmt = $this->db->prepare(
<<< 'SQL'
    SELECT
        id, type, message, date_time 
    FROM 
        user_messages
    WHERE
        user_id = :user_id
    ORDER BY
        date_time DESC
SQL
        );

        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function addUserMessage(string $userId, string $type, string $message): void
    {
        $this->addUser($userId);
        $stmt = $this->db->prepare(
<<< 'SQL'
    INSERT INTO user_messages 
        (user_id, type, message, date_time) 
    VALUES
        (:user_id, :type, :message, :date_time)
SQL
        );

        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->bindValue(':type', $type, PDO::PARAM_STR);
        $stmt->bindValue(':message', $message, PDO::PARAM_STR);
        $stmt->bindValue(':date_time', $this->dateTime->format(DateTime::ATOM), PDO::PARAM_STR);
        $stmt->execute();
    }

    public function cleanExpiredCertificates(DateTimeInterface $dateTime): void
    {
        $stmt = $this->db->prepare('DELETE FROM certificates WHERE valid_to < :date_time');
        $stmt->bindValue(':date_time', $dateTime->format(DateTime::ATOM), PDO::PARAM_STR);

        $stmt->execute();
    }

    public function getStats(string $profileId): iterable
    {
        $stmt = $this->db->prepare(
<<< 'SQL'
    SELECT 
        user_id,
        common_name, 
        connected_at, 
        disconnected_at, 
        bytes_transferred
    FROM 
        connection_log
    WHERE
        profile_id = :profile_id
    AND
        disconnected_at IS NOT NULL
    ORDER BY
        connected_at
SQL
        );

        $stmt->bindValue(':profile_id', $profileId, PDO::PARAM_STR);
        $stmt->execute();
        while ($entry = $stmt->fetch(PDO::FETCH_ASSOC)) {
            yield $entry;
        }
    }

    public function init(): void
    {
        $this->migration->init();
    }

    public function update(): void
    {
        $this->migration->run();
    }

    private function addUser(string $userId): void
    {
        $stmt = $this->db->prepare(
<<< 'SQL'
    SELECT 
        COUNT(*)
    FROM 
        users
    WHERE user_id = :user_id
SQL
        );

        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->execute();

        if (1 !== (int) $stmt->fetchColumn()) {
            // user does not exist yet
            $stmt = $this->db->prepare(
<<< 'SQL'
    INSERT INTO 
        users (
            user_id,
            session_expires_at,
            permission_list,
            is_disabled
        )
    VALUES (
        :user_id,
        :session_expires_at,
        :permission_list,
        :is_disabled
    )
SQL
            );
            $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
            $stmt->bindValue(':session_expires_at', $this->dateTime->format(DateTime::ATOM), PDO::PARAM_STR);
            $stmt->bindValue(':permission_list', '[]', PDO::PARAM_STR);
            $stmt->bindValue(':is_disabled', false, PDO::PARAM_BOOL);
            $stmt->execute();
        }
    }
}
