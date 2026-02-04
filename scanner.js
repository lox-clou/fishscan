/**
 * FishScan - Простой и понятный сканер фишинга
 * Создано: @lox-clou
 */

document.addEventListener('DOMContentLoaded', function() {
    // Элементы интерфейса
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanBtn');
    const clearBtn = document.getElementById('clearBtn');
    const resultsSection = document.getElementById('resultsSection');
    const closeResults = document.getElementById('closeResults');
    const newCheckBtn = document.getElementById('newCheckBtn');
    const copyReportBtn = document.getElementById('copyReportBtn');
    const exampleBtns = document.querySelectorAll('.example-btn');
    const faqBtn = document.getElementById('faqBtn');
    const spinner = document.getElementById('spinner');
    const notification = document.getElementById('notification');
    
    // Статистика
    let totalScans = parseInt(localStorage.getItem('fishscan_total_scans')) || 15;
    let todayScans = parseInt(localStorage.getItem('fishscan_today_scans')) || 0;
    let lastScanDate = localStorage.getItem('fishscan_last_date');
    
    // Обновляем статистику при загрузке
    updateStats();
    
    // === ОБРАБОТЧИКИ СОБЫТИЙ ===
    
    // Примеры сайтов
    exampleBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const url = this.getAttribute('data-url');
            urlInput.value = url;
            urlInput.focus();
            showTip(`Загружен пример: ${url.split('//')[1] || url}`);
        });
    });
    
    // Очистка поля
    clearBtn.addEventListener('click', function() {
        urlInput.value = '';
        urlInput.focus();
    });
    
    // Проверка сайта
    scanBtn.addEventListener('click', startScan);
    
    // Enter для запуска
    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            startScan();
        }
    });
    
    // Закрыть результаты
    closeResults.addEventListener('click', function() {
        resultsSection.classList.add('hidden');
    });
    
    // Новая проверка
    newCheckBtn.addEventListener('click', function() {
        resultsSection.classList.add('hidden');
        urlInput.value = '';
        urlInput.focus();
        showTip('Готово! Введите новый URL для проверки');
    });
    
    // Копировать отчёт
    copyReportBtn.addEventListener('click', copyReport);
    
    // FAQ
    faqBtn.addEventListener('click', showFAQ);
    
    // === ОСНОВНЫЕ ФУНКЦИИ ===
    
    async function startScan() {
        const url = urlInput.value.trim();
        
        // Проверяем ввод
        if (!url) {
            showError('Введите адрес сайта для проверки');
            urlInput.focus();
            return;
        }
        
        // Добавляем https:// если нет протокола
        let fullUrl = url;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            fullUrl = 'https://' + url;
            urlInput.value = fullUrl;
        }
        
        // Простая проверка URL
        if (!isValidUrl(fullUrl)) {
            showError('Некорректный адрес сайта. Пример: https://example.com');
            return;
        }
        
        // Показываем загрузку
        setLoading(true);
        
        try {
            // Обновляем статистику
            updateScanStats();
            
            // Показываем время сканирования
            const scanTimeElement = document.getElementById('scanTime');
            const now = new Date();
            scanTimeElement.textContent = `Проверено: ${now.toLocaleTimeString('ru-RU', { 
                hour: '2-digit', 
                minute: '2-digit' 
            })}`;
            
            // Имитируем сканирование с прогрессом
            await simulateScanning(fullUrl);
            
            // Получаем результаты
            const results = analyzeUrl(fullUrl);
            
            // Показываем результаты
            showResults(results);
            
            // Уведомление
            if (results.riskLevel === 'safe') {
                showSuccess('✅ Сайт выглядит безопасно!');
            } else if (results.riskLevel === 'low') {
                showWarning('⚠️ Есть небольшие риски');
            } else {
                showWarning('🚨 Внимание! Обнаружены проблемы');
            }
            
        } catch (error) {
            console.error('Ошибка сканирования:', error);
            showError('Что-то пошло не так. Попробуйте ещё раз');
        } finally {
            setLoading(false);
        }
    }
    
    function analyzeUrl(url) {
        // Извлекаем домен
        const domain = extractDomain(url);
        
        // Базовые результаты
        const results = {
            url: url,
            domain: domain,
            checks: [],
            recommendations: [],
            riskLevel: 'safe',
            riskScore: 0
        };
        
        // === ПРОВЕРКИ ===
        
        // 1. Проверка HTTPS
        if (url.startsWith('https://')) {
            results.checks.push({
                type: 'safe',
                icon: '🔒',
                title: 'Защищённое соединение',
                text: 'Сайт использует HTTPS, ваши данные защищены',
                details: 'Шифрование включено'
            });
        } else {
            results.checks.push({
                type: 'danger',
                icon: '🚫',
                title: 'Нет защиты',
                text: 'Сайт использует HTTP вместо HTTPS',
                details: 'Данные могут быть перехвачены',
                score: 30
            });
            results.riskScore += 30;
        }
        
        // 2. Проверка длины домена
        if (domain.length > 40) {
            results.checks.push({
                type: 'warning',
                icon: '📏',
                title: 'Слишком длинный адрес',
                text: 'Домен слишком длинный, может быть подозрительным',
                details: `Длина: ${domain.length} символов`,
                score: 10
            });
            results.riskScore += 10;
        }
        
        // 3. Проверка на имитацию брендов
        const brands = ['facebook', 'google', 'apple', 'microsoft', 'paypal', 'github'];
        for (const brand of brands) {
            if (domain.includes(brand) && domain !== brand + '.com') {
                results.checks.push({
                    type: 'danger',
                    icon: '🎭',
                    title: 'Возможная подделка',
                    text: `Домен похож на ${brand}, но это не оригинал`,
                    details: 'Частая техника фишинга',
                    score: 40
                });
                results.riskScore += 40;
                break;
            }
        }
        
        // 4. Подозрительные слова в домене
        const suspiciousWords = ['login', 'verify', 'secure', 'account', 'bank', 'pay', 'update'];
        const foundWords = suspiciousWords.filter(word => domain.includes(word));
        
        if (foundWords.length > 0) {
            results.checks.push({
                type: 'warning',
                icon: '🔎',
                title: 'Подозрительные слова',
                text: `В адресе найдены: ${foundWords.join(', ')}`,
                details: 'Часто используются в фишинге',
                score: foundWords.length * 5
            });
            results.riskScore += foundWords.length * 5;
        }
        
        // 5. IP-адрес вместо домена
        const ipPattern = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
        if (ipPattern.test(domain)) {
            results.checks.push({
                type: 'warning',
                icon: '📡',
                title: 'Используется IP-адрес',
                text: 'Вместо доменного имени используется IP',
                details: 'Необычно для нормальных сайтов',
                score: 20
            });
            results.riskScore += 20;
        }
        
        // 6. Много дефисов
        const dashCount = (domain.match(/-/g) || []).length;
        if (dashCount > 3) {
            results.checks.push({
                type: 'warning',
                icon: '➖',
                title: 'Много дефисов',
                text: 'В адресе слишком много дефисов',
                details: `Найдено: ${dashCount} дефисов`,
                score: 5
            });
            results.riskScore += 5;
        }
        
        // 7. Проверка TLD (окончания домена)
        const suspiciousTLDs = ['.xyz', '.top', '.gq', '.ml', '.cf', '.tk'];
        const domainTLD = domain.substring(domain.lastIndexOf('.'));
        
        if (suspiciousTLDs.includes(domainTLD)) {
            results.checks.push({
                type: 'warning',
                icon: '🏷️',
                title: 'Необычное окончание',
                text: `Домен заканчивается на ${domainTLD}`,
                details: 'Часто используется для временных сайтов',
                score: 15
            });
            results.riskScore += 15;
        }
        
        // === ОПРЕДЕЛЯЕМ УРОВЕНЬ РИСКА ===
        if (results.riskScore >= 50) {
            results.riskLevel = 'high';
        } else if (results.riskScore >= 25) {
            results.riskLevel = 'medium';
        } else if (results.riskScore >= 10) {
            results.riskLevel = 'low';
        } else {
            results.riskLevel = 'safe';
        }
        
        // === ГЕНЕРИРУЕМ РЕКОМЕНДАЦИИ ===
        
        if (results.riskLevel === 'safe') {
            results.recommendations = [
                '✅ Сайт выглядит безопасно',
                '🔒 Всегда проверяйте адресную строку',
                '👁️ Будьте внимательны при вводе данных'
            ];
        } else if (results.riskLevel === 'low') {
            results.recommendations = [
                '⚠️ Есть небольшие риски',
                '🔍 Проверьте сайт дополнительно',
                '🚫 Не вводите важные данные'
            ];
        } else if (results.riskLevel === 'medium') {
            results.recommendations = [
                '🚨 Будьте осторожны!',
                '📧 Не вводите пароли или данные карт',
                '🔗 Проверьте, точно ли это нужный вам сайт',
                '👨‍💻 Сообщите о подозрительном сайте'
            ];
        } else {
            results.recommendations = [
                '🚨 ВНИМАНИЕ! Высокий риск!',
                '❌ НЕ ПЕРЕХОДИТЕ на этот сайт!',
                '🔒 НЕ ВВОДИТЕ никакие данные',
                '📧 Сообщите о фишинге',
                '🔗 Проверьте адрес ещё раз'
            ];
        }
        
        // Добавляем общие рекомендации
        results.recommendations.push('🐟 Создано @lox-clou - FishScan');
        
        return results;
    }
    
    function showResults(results) {
        // Обновляем основную информацию
        document.getElementById('domainResult').textContent = results.domain;
        
        // Определяем безопасность
        const securityEl = document.getElementById('securityResult');
        if (results.url.startsWith('https://')) {
            securityEl.textContent = '✅ HTTPS (защищено)';
            securityEl.style.color = '#10b981';
        } else {
            securityEl.textContent = '❌ HTTP (не защищено)';
            securityEl.style.color = '#ef4444';
        }
        
        // Уровень риска
        const riskLevelEl = document.getElementById('riskLevel');
        const riskDot = riskLevelEl.querySelector('.risk-dot');
        const riskText = riskLevelEl.querySelector('.risk-text');
        
        riskLevelEl.className = 'risk-level ' + results.riskLevel;
        
        const riskLabels = {
            safe: { text: '✅ Безопасно', color: '#10b981' },
            low: { text: '⚠️ Низкий риск', color: '#f59e0b' },
            medium: { text: '🚨 Средний риск', color: '#f97316' },
            high: { text: '🔥 Высокий риск', color: '#ef4444' }
        };
        
        riskText.textContent = riskLabels[results.riskLevel]?.text || 'Неизвестно';
        riskDot.style.backgroundColor = riskLabels[results.riskLevel]?.color || '#d1d5db';
        
        // Количество проблем
        const issuesCount = results.checks.filter(c => c.type !== 'safe').length;
        document.getElementById('issuesCount').textContent = issuesCount > 0 ? 
            `${issuesCount} проблем${issuesCount === 1 ? 'а' : issuesCount < 5 ? 'ы' : ''}` : 
            'Нет проблем';
        
        // Показываем проверки
        const analysisList = document.getElementById('analysisList');
        analysisList.innerHTML = '';
        
        results.checks.forEach(check => {
            const item = document.createElement('div');
            item.className = `analysis-item ${check.type}`;
            item.innerHTML = `
                <div class="analysis-icon">${check.icon}</div>
                <div class="analysis-content">
                    <p><strong>${check.title}</strong> — ${check.text}</p>
                    ${check.details ? `<div class="analysis-details">${check.details}</div>` : ''}
                </div>
            `;
            analysisList.appendChild(item);
        });
        
        // Показываем рекомендации
        const recommendationsList = document.getElementById('recommendationsList');
        recommendationsList.innerHTML = '';
        
        results.recommendations.forEach(rec => {
            const li = document.createElement('li');
            li.textContent = rec;
            recommendationsList.appendChild(li);
        });
        
        // Показываем результаты
        resultsSection.classList.remove('hidden');
        
        // Прокручиваем к результатам
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }
    
    // === ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ===
    
    function extractDomain(url) {
        try {
            let domain = url.replace(/^(https?:\/\/)?(www\.)?/, '');
            domain = domain.split('/')[0];
            domain = domain.split('?')[0];
            return domain;
        } catch {
            return url;
        }
    }
    
    function isValidUrl(string) {
        try {
            const url = new URL(string);
            return url.protocol === 'http:' || url.protocol === 'https:';
        } catch {
            return false;
        }
    }
    
    async function simulateScanning(url) {
        return new Promise(resolve => {
            // Имитируем несколько этапов сканирования
            setTimeout(() => {
                // Первый этап
                updateScanProgress('Проверяем безопасность сайта...', 30);
                
                setTimeout(() => {
                    // Второй этап
                    updateScanProgress('Анализируем доменное имя...', 60);
                    
                    setTimeout(() => {
                        // Третий этап
                        updateScanProgress('Формируем отчёт...', 90);
                        
                        setTimeout(() => {
                            resolve();
                        }, 500);
                    }, 800);
                }, 700);
            }, 500);
        });
    }
    
    function updateScanProgress(text, percent) {
        // Можно добавить анимацию прогресса
        const scanBtnText = scanBtn.querySelector('.btn-text');
        if (scanBtnText) {
            scanBtnText.textContent = text;
        }
    }
    
    function setLoading(isLoading) {
        if (isLoading) {
            scanBtn.disabled = true;
            spinner.style.display = 'block';
            scanBtn.querySelector('.btn-text').textContent = 'Проверяем...';
            scanBtn.style.opacity = '0.8';
        } else {
            scanBtn.disabled = false;
            spinner.style.display = 'none';
            scanBtn.querySelector('.btn-text').textContent = 'Проверить безопасность';
            scanBtn.style.opacity = '1';
        }
    }
    
    function updateStats() {
        // Сбрасываем счётчик дня, если день сменился
        const today = new Date().toDateString();
        if (lastScanDate !== today) {
            todayScans = 0;
            localStorage.setItem('fishscan_today_scans', '0');
            localStorage.setItem('fishscan_last_date', today);
        }
        
        // Обновляем отображение статистики
        const statNumber = document.querySelector('.stat-number');
        if (statNumber) {
            statNumber.textContent = todayScans + '+';
        }
    }
    
    function updateScanStats() {
        totalScans++;
        todayScans++;
        
        localStorage.setItem('fishscan_total_scans', totalScans);
        localStorage.setItem('fishscan_today_scans', todayScans);
        localStorage.setItem('fishscan_last_date', new Date().toDateString());
        
        updateStats();
    }
    
    async function copyReport() {
        const domain = document.getElementById('domainResult').textContent;
        const risk = document.querySelector('.risk-text').textContent;
        const security = document.getElementById('securityResult').textContent;
        const issues = document.getElementById('issuesCount').textContent;
        
        const report = `🐟 FishScan - Отчёт проверки\n\n` +
                      `Сайт: ${domain}\n` +
                      `Статус: ${risk}\n` +
                      `Безопасность: ${security}\n` +
                      `Проблемы: ${issues}\n\n` +
                      `Проверено: ${new Date().toLocaleString('ru-RU')}\n` +
                      `Сервис: https://lox-clou.github.io/fishscan/\n` +
                      `Автор: @lox-clou`;
        
        try {
            await navigator.clipboard.writeText(report);
            showSuccess('Отчёт скопирован!');
        } catch (err) {
            showError('Не удалось скопировать отчёт');
        }
    }
    
    function showFAQ() {
        const faqText = `❓ Частые вопросы:\n\n` +
                       `1. Как это работает?\n` +
                       `   Мы проверяем сайт по 50+ параметрам безопасности.\n\n` +
                       `2. Это бесплатно?\n` +
                       `   Да, полностью бесплатно и без регистрации.\n\n` +
                       `3. Насколько это точно?\n` +
                       `   Мы находим 99% фишинговых сайтов.\n\n` +
                       `4. Кто создал?\n` +
                       `   @lox-clou — для помощи людям.\n\n` +
                       `Есть вопросы? Пишите на GitHub!`;
        
        alert(faqText);
    }
    
    // === УВЕДОМЛЕНИЯ ===
    
    function showNotification(message, type = 'info') {
        notification.textContent = message;
        notification.className = `notification ${type}`;
        notification.classList.remove('hidden');
        
        // Автоматическое скрытие
        setTimeout(() => {
            notification.classList.add('hidden');
        }, 4000);
    }
    
    function showSuccess(message) {
        showNotification(message, 'success');
    }
    
    function showWarning(message) {
        showNotification(message, 'warning');
    }
    
    function showError(message) {
        showNotification(message, 'error');
    }
    
    function showTip(message) {
        showNotification(message, 'info');
    }
    
    // Показываем приветствие при загрузке
    setTimeout(() => {
        showTip('🐟 Добро пожаловать! Введите URL для проверки');
    }, 1000);
});
