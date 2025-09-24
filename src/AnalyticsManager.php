<?php

namespace WebAuthn;

use PDO;
use Exception;

/**
 * Менеджер аналитики и аудита для WebAuthn приложения
 * Отвечает за сбор, анализ и отчетность по данным пользователей
 */
class AnalyticsManager
{
    private Database $db;
    private PDO $pdo;

    public function __construct(Database $db)
    {
        $this->db = $db;
        $this->pdo = $db->getPdo();
    }

    /**
     * Логирование действий пользователя для аудита
     */
    public function logUserAction(
        ?string $userId,
        string $actionType,
        string $result,
        ?string $sessionId = null,
        ?array $actionDetails = null,
        ?string $errorMessage = null,
        int $riskScore = 0
    ): bool {
        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO audit_log (
                    user_id, session_id, ip_address, user_agent, action_type,
                    action_details, result, error_message, risk_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");

            $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
            $actionDetailsJson = $actionDetails ? json_encode($actionDetails) : null;

            return $stmt->execute([
                $userId, $sessionId, $ipAddress, $userAgent, $actionType,
                $actionDetailsJson, $result, $errorMessage, $riskScore
            ]);
        } catch (Exception $e) {
            error_log("AnalyticsManager: Failed to log action - " . $e->getMessage());
            return false;
        }
    }

    /**
     * Записать аналитику устройства
     */
    public function recordDeviceAnalytics(
        string $userId,
        string $deviceHash,
        array $deviceFingerprint,
        bool $loginSuccess = true,
        ?array $locationData = null,
        bool $isTrusted = false
    ): bool {
        try {
            // Проверяем существует ли уже запись для этого устройства
            $stmt = $this->pdo->prepare("
                SELECT id, total_logins, failed_attempts 
                FROM device_analytics 
                WHERE user_id = ? AND device_hash = ?
            ");
            $stmt->execute([$userId, $deviceHash]);
            $existing = $stmt->fetch(PDO::FETCH_ASSOC);

            $deviceInfo = DeviceHelper::getDeviceInfo($deviceFingerprint['userAgent'] ?? '');
            $ipAddress = $_SERVER['REMOTE_ADDR'] ?? null;

            if ($existing) {
                // Обновляем существующую запись
                $newTotalLogins = $loginSuccess ? $existing['total_logins'] + 1 : $existing['total_logins'];
                $newFailedAttempts = !$loginSuccess ? $existing['failed_attempts'] + 1 : $existing['failed_attempts'];

                $stmt = $this->pdo->prepare("
                    UPDATE device_analytics SET
                        last_seen = CURRENT_TIMESTAMP,
                        total_logins = ?,
                        failed_attempts = ?,
                        location_data = ?,
                        is_trusted = ?,
                        last_ip = ?,
                        operating_system = ?,
                        browser_name = ?,
                        screen_resolution = ?,
                        timezone = ?
                    WHERE id = ?
                ");

                return $stmt->execute([
                    $newTotalLogins,
                    $newFailedAttempts,
                    $locationData ? json_encode($locationData) : null,
                    $isTrusted,
                    $ipAddress,
                    $deviceInfo['deviceType'],
                    $deviceInfo['browserName'],
                    ($deviceFingerprint['screenWidth'] ?? '') . 'x' . ($deviceFingerprint['screenHeight'] ?? ''),
                    $deviceFingerprint['timezone'] ?? null,
                    $existing['id']
                ]);
            } else {
                // Создаем новую запись
                $stmt = $this->pdo->prepare("
                    INSERT INTO device_analytics (
                        user_id, device_hash, device_fingerprint, total_logins,
                        failed_attempts, location_data, is_trusted, last_ip,
                        operating_system, browser_name, screen_resolution, timezone
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ");

                return $stmt->execute([
                    $userId,
                    $deviceHash,
                    json_encode($deviceFingerprint),
                    $loginSuccess ? 1 : 0,
                    $loginSuccess ? 0 : 1,
                    $locationData ? json_encode($locationData) : null,
                    $isTrusted,
                    $ipAddress,
                    $deviceInfo['deviceType'],
                    $deviceInfo['browserName'],
                    ($deviceFingerprint['screenWidth'] ?? '') . 'x' . ($deviceFingerprint['screenHeight'] ?? ''),
                    $deviceFingerprint['timezone'] ?? null
                ]);
            }
        } catch (Exception $e) {
            error_log("AnalyticsManager: Failed to record device analytics - " . $e->getMessage());
            return false;
        }
    }

    /**
     * Записать аналитику сессии
     */
    public function recordSessionAnalytics(
        string $sessionId,
        string $userId,
        string $deviceHash,
        string $endReason = null
    ): bool {
        try {
            $stmt = $this->pdo->prepare("
                SELECT id, started_at 
                FROM session_analytics 
                WHERE session_id = ?
            ");
            $stmt->execute([$sessionId]);
            $existing = $stmt->fetch(PDO::FETCH_ASSOC);

            $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;

            if ($existing) {
                // Обновляем существующую сессию (завершение)
                if ($endReason) {
                    $startTime = new \DateTime($existing['started_at']);
                    $endTime = new \DateTime();
                    $duration = $endTime->getTimestamp() - $startTime->getTimestamp();

                    $stmt = $this->pdo->prepare("
                        UPDATE session_analytics SET
                            ended_at = CURRENT_TIMESTAMP,
                            end_reason = ?,
                            duration_seconds = ?
                        WHERE id = ?
                    ");

                    return $stmt->execute([$endReason, $duration, $existing['id']]);
                } else {
                    // Обновляем активность
                    $stmt = $this->pdo->prepare("
                        UPDATE session_analytics SET
                            last_activity = CURRENT_TIMESTAMP,
                            api_calls = api_calls + 1
                        WHERE id = ?
                    ");

                    return $stmt->execute([$existing['id']]);
                }
            } else {
                // Создаем новую сессию
                $stmt = $this->pdo->prepare("
                    INSERT INTO session_analytics (
                        session_id, user_id, device_hash, ip_address, user_agent
                    ) VALUES (?, ?, ?, ?, ?)
                ");

                return $stmt->execute([$sessionId, $userId, $deviceHash, $ipAddress, $userAgent]);
            }
        } catch (Exception $e) {
            error_log("AnalyticsManager: Failed to record session analytics - " . $e->getMessage());
            return false;
        }
    }

    /**
     * Записать инцидент безопасности
     */
    public function recordSecurityIncident(
        string $incidentType,
        string $severity,
        ?string $userId = null,
        ?array $indicators = null,
        ?string $attackVector = null
    ): int|false {
        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO security_incidents (
                    incident_type, severity, user_id, ip_address, user_agent,
                    attack_vector, indicators
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ");

            $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
            $indicatorsJson = $indicators ? json_encode($indicators) : null;

            if ($stmt->execute([
                $incidentType, $severity, $userId, $ipAddress, $userAgent,
                $attackVector, $indicatorsJson
            ])) {
                return $this->pdo->lastInsertId();
            }

            return false;
        } catch (Exception $e) {
            error_log("AnalyticsManager: Failed to record security incident - " . $e->getMessage());
            return false;
        }
    }

    /**
     * Записать аналитику WebAuthn
     */
    public function recordWebAuthnAnalytics(
        string $userId,
        string $credentialId,
        ?string $authenticatorType = null,
        ?string $attestationFormat = null,
        ?array $transportMethods = null,
        ?string $algorithm = null,
        bool $isUsage = false
    ): bool {
        try {
            $credentialIdBinary = hex2bin($credentialId);

            // Проверяем существует ли запись
            $stmt = $this->pdo->prepare("
                SELECT id, usage_count, failed_usage_count 
                FROM webauthn_analytics 
                WHERE credential_id = ?
            ");
            $stmt->execute([$credentialIdBinary]);
            $existing = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($existing) {
                // Обновляем существующую запись
                if ($isUsage) {
                    $stmt = $this->pdo->prepare("
                        UPDATE webauthn_analytics SET
                            last_used = CURRENT_TIMESTAMP,
                            usage_count = usage_count + 1
                        WHERE id = ?
                    ");
                    return $stmt->execute([$existing['id']]);
                }
            } else {
                // Создаем новую запись
                $stmt = $this->pdo->prepare("
                    INSERT INTO webauthn_analytics (
                        user_id, credential_id, authenticator_type, attestation_format,
                        transport_methods, algorithm
                    ) VALUES (?, ?, ?, ?, ?, ?)
                ");

                return $stmt->execute([
                    $userId,
                    $credentialIdBinary,
                    $authenticatorType,
                    $attestationFormat,
                    $transportMethods ? json_encode($transportMethods) : null,
                    $algorithm
                ]);
            }

            return true;
        } catch (Exception $e) {
            error_log("AnalyticsManager: Failed to record WebAuthn analytics - " . $e->getMessage());
            return false;
        }
    }

    /**
     * Получить статистику пользователя
     */
    public function getUserStats(string $userId): array
    {
        try {
            $stats = [];

            // Основная информация о пользователе
            $stmt = $this->pdo->prepare("
                SELECT login_count, failed_login_count, last_login, account_status, risk_score
                FROM users WHERE user_id = ?
            ");
            $stmt->execute([$userId]);
            $stats['user'] = $stmt->fetch(PDO::FETCH_ASSOC);

            // Статистика устройств
            $stmt = $this->pdo->prepare("
                SELECT COUNT(*) as device_count, 
                       SUM(total_logins) as total_logins,
                       SUM(failed_attempts) as total_failed_attempts
                FROM device_analytics WHERE user_id = ?
            ");
            $stmt->execute([$userId]);
            $stats['devices'] = $stmt->fetch(PDO::FETCH_ASSOC);

            // Последние действия
            $stmt = $this->pdo->prepare("
                SELECT action_type, result, created_at
                FROM audit_log 
                WHERE user_id = ? 
                ORDER BY created_at DESC 
                LIMIT 10
            ");
            $stmt->execute([$userId]);
            $stats['recent_actions'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // WebAuthn статистика
            $stmt = $this->pdo->prepare("
                SELECT COUNT(*) as authenticator_count,
                       SUM(usage_count) as total_usage,
                       MAX(last_used) as last_authenticator_use
                FROM webauthn_analytics WHERE user_id = ?
            ");
            $stmt->execute([$userId]);
            $stats['webauthn'] = $stmt->fetch(PDO::FETCH_ASSOC);

            return $stats;
        } catch (Exception $e) {
            error_log("AnalyticsManager: Failed to get user stats - " . $e->getMessage());
            return [];
        }
    }

    /**
     * Получить сводку инцидентов безопасности
     */
    public function getSecuritySummary(?string $userId = null, int $days = 7): array
    {
        try {
            $whereClause = $userId ? "WHERE user_id = ?" : "WHERE 1=1";
            $params = $userId ? [$userId] : [];

            $stmt = $this->pdo->prepare("
                SELECT 
                    incident_type,
                    severity,
                    COUNT(*) as count,
                    MAX(first_detected) as latest_incident
                FROM security_incidents 
                $whereClause
                AND first_detected >= DATE_SUB(NOW(), INTERVAL ? DAY)
                GROUP BY incident_type, severity
                ORDER BY severity DESC, count DESC
            ");

            $params[] = $days;
            $stmt->execute($params);

            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (Exception $e) {
            error_log("AnalyticsManager: Failed to get security summary - " . $e->getMessage());
            return [];
        }
    }

    /**
     * Обновить счетчики пользователя при входе
     */
    public function updateUserLoginStats(string $userId, bool $success = true): bool
    {
        try {
            if ($success) {
                $stmt = $this->pdo->prepare("
                    UPDATE users SET 
                        login_count = login_count + 1,
                        last_login = CURRENT_TIMESTAMP,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = ?
                ");
            } else {
                $stmt = $this->pdo->prepare("
                    UPDATE users SET 
                        failed_login_count = failed_login_count + 1,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = ?
                ");
            }

            return $stmt->execute([$userId]);
        } catch (Exception $e) {
            error_log("AnalyticsManager: Failed to update user login stats - " . $e->getMessage());
            return false;
        }
    }

    /**
     * Получить топ угроз по IP адресам
     */
    public function getTopThreatIPs(int $limit = 10, int $days = 7): array
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT 
                    ip_address,
                    COUNT(*) as incident_count,
                    MAX(first_detected) as latest_incident,
                    GROUP_CONCAT(DISTINCT incident_type) as incident_types
                FROM security_incidents 
                WHERE first_detected >= DATE_SUB(NOW(), INTERVAL ? DAY)
                GROUP BY ip_address
                ORDER BY incident_count DESC
                LIMIT ?
            ");

            $stmt->execute([$days, $limit]);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (Exception $e) {
            error_log("AnalyticsManager: Failed to get top threat IPs - " . $e->getMessage());
            return [];
        }
    }
}
