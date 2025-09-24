<?php
/**
 * Запуск всех тестов проекта
 */

echo "🚀 Запуск полного набора тестов WebAuthn проекта\n";
echo "=" . str_repeat("=", 50) . "\n\n";

$testsDir = __DIR__;
$testFiles = [
    'test_db.php' => 'Тестирование подключения к БД',
    'DatabaseTest.php' => 'Тестирование Database класса',
    'DeviceHelperTest.php' => 'Тестирование DeviceHelper класса',
    'WebAuthnHelperTest.php' => 'Тестирование WebAuthnHelper класса',
    'SessionManagerTest.php' => 'Тестирование SessionManager класса',
    'ApiTest.php' => 'Тестирование WebAuthn API',
    'EdgeCasesTest.php' => 'Тестирование крайних случаев'
];

$allPassed = true;
$totalTests = 0;
$passedTests = 0;
$failedTests = 0;

foreach ($testFiles as $testFile => $description) {
    echo "📋 {$description}\n";
    echo "-" . str_repeat("-", 50) . "\n";
    
    $testPath = $testsDir . '/' . $testFile;
    
    if (!file_exists($testPath)) {
        echo "❌ Файл теста не найден: {$testFile}\n\n";
        $allPassed = false;
        continue;
    }
    
    // Запускаем тест и захватываем вывод
    ob_start();
    $exitCode = 0;
    
    try {
        include $testPath;
    } catch (Exception $e) {
        echo "❌ Ошибка выполнения теста: " . $e->getMessage() . "\n";
        $exitCode = 1;
    }
    
    $output = ob_get_clean();
    echo $output;
    
    // Анализируем результат
    if ($exitCode !== 0 || strpos($output, 'ТЕСТЫ НЕ ПРОЙДЕНЫ') !== false || strpos($output, 'ТЕСТЫ API НЕ ПРОЙДЕНЫ') !== false) {
        $allPassed = false;
        $failedTests++;
    } else {
        $passedTests++;
    }
    
    $totalTests++;
    echo "\n";
}

echo "=" . str_repeat("=", 50) . "\n";
echo "📊 ОБЩИЕ РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ:\n";
echo "✅ Успешных наборов тестов: {$passedTests}\n";
echo "❌ Проваленных наборов тестов: {$failedTests}\n";
echo "📝 Всего наборов тестов: {$totalTests}\n";

if ($allPassed) {
    echo "\n🎉 ВСЕ ТЕСТЫ ПРОЕКТА ПРОЙДЕНЫ УСПЕШНО!\n";
    echo "✨ Код готов к рефакторингу и развертыванию.\n";
} else {
    echo "\n❌ НЕКОТОРЫЕ ТЕСТЫ НЕ ПРОШЛИ!\n";
    echo "🔧 Необходимо исправить ошибки перед продолжением разработки.\n";
    exit(1);
}
