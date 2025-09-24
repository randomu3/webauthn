<?php
/**
 * Скрипт очистки базы данных для чистых экспериментов
 * Удаляет все пользовательские данные, но сохраняет структуру таблиц
 */

require_once __DIR__ . '/../src/Database.php';

use WebAuthn\Database;

echo "🧹 Очистка базы данных для чистого эксперимента..." . PHP_EOL;
echo "=================================================" . PHP_EOL;

try {
    $db = new Database();
    $pdo = $db->getPdo();
    
    // Отключаем проверки внешних ключей
    $pdo->exec('SET FOREIGN_KEY_CHECKS = 0');
    
    // Список таблиц для очистки (в правильном порядке)
    $tablesToClean = [
        'session_analytics',
        'webauthn_analytics', 
        'user_locations',
        'security_incidents',
        'device_analytics',
        'audit_log',
        'emergency_tokens',
        'recovery_codes',
        'blocked_ips',
        'rate_limits',
        'user_sessions',
        'user_credentials', 
        'users',
        'device_fingerprints'
    ];
    
    $totalCleaned = 0;
    
    foreach ($tablesToClean as $table) {
        try {
            // Получаем количество записей до очистки
            $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM `{$table}`");
            $stmt->execute();
            $beforeCount = $stmt->fetch()['count'];
            
            // Очищаем таблицу
            $pdo->exec("TRUNCATE TABLE `{$table}`");
            
            echo "✅ {$table}: очищено {$beforeCount} записей" . PHP_EOL;
            $totalCleaned += $beforeCount;
            
        } catch (Exception $e) {
            echo "⚠️  {$table}: " . $e->getMessage() . PHP_EOL;
        }
    }
    
    // Включаем обратно проверки внешних ключей
    $pdo->exec('SET FOREIGN_KEY_CHECKS = 1');
    
    echo PHP_EOL . "🎉 Очистка завершена успешно!" . PHP_EOL;
    echo "📊 Всего удалено записей: {$totalCleaned}" . PHP_EOL;
    echo "🗄️  Структура таблиц сохранена" . PHP_EOL;
    echo "🚀 База данных готова для чистого эксперимента!" . PHP_EOL;
    
} catch (Exception $e) {
    echo "❌ Ошибка при очистке БД: " . $e->getMessage() . PHP_EOL;
    exit(1);
}
