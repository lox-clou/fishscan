/**
 * FishScan - Сканер фишинговых URL
 * Разработано: @lox-clou
 * GitHub: https://github.com/lox-clou/fishscan
 */

class FishScanner {
    constructor() {
        this.suspiciousKeywords = [
            'login', 'verify', 'secure', 'account', 'banking',
            'update', 'confirm', 'password', 'wallet', 'crypto',
            'paypal', 'facebook', 'google', 'microsoft', 'apple',
            'amazon', 'instagram', 'twitter', 'netflix', 'steam',
            'security', 'validation', 'authentication', 'signin'
        ];
        
        this.legitDomains = [
            'google.com', 'facebook.com', 'github.com', 'microsoft.com',
            'apple.com', 'amazon.com', 'paypal.com', 'steamcommunity.com',
            'twitter.com', 'instagram.com', 'netflix.com', 'youtube.com',
            'linkedin.com', 'whatsapp.com', 'telegram.org'
        ];
    }
    
    async scan(url) {
        return new Promise((resolve) => {
            // Имитация загрузки (в реальном проекте здесь был бы запрос к API)
            setTimeout(() => {
                try {
                    const results = this._analyzeURL(url);
                    resolve(results);
                } catch (error) {
                    console.error('Ошибка анализа:', error);
                    resolve({
                        error: 'Ошибка анализа URL',
                        risk_score: 0,
                        risk_level: 'low'
                    });
                }
            }, 1200);
        });
    }
    
    _analyzeURL(url) {
        const results = {
            url: url,
            domain: '',
            risk_score: 0,
            warnings: [],
            checks: {},
            is_phishing: false
        };
        
        try {
            // Извлекаем домен
            let domain = url.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '');
            domain = domain.split('/')[0];
            domain = domain.split('?')[0];
            results.domain = domain;
            
            // 1. Проверка HTTPS
            const hasHTTPS = url.startsWith('https://');
            results.checks.https = hasHTTPS;
            if (!hasHTTPS) {
                results.warnings.push({
                    text: 'Сайт использует HTTP вместо HTTPS',
                    level: 'medium',
                    details: 'Данные передаются в незашифрованном виде'
                });
                results.risk_score += 20;
            }
            
            // 2. Проверка длины домена
            if (domain.length > 50) {
                results.warnings.push({
                    text: 'Слишком длинное доменное имя',
                    level: 'low',
                    details: 'Длина: ' + domain.length + ' символов'
                });
                results.risk_score += 10;
            }
            
            // 3. Похожесть на бренды
            let brandMatch = null;
            for (const legit of this.legitDomains) {
                if (domain.includes(legit) && domain !== legit) {
                    brandMatch = legit;
                    results.warnings.push({
                        text: `Домен имитирует ${legit}`,
                        level: 'high',
                        details: 'Частая техника фишинга'
                    });
                    results.risk_score += 40;
                    results.is_phishing = true;
                    break;
                }
            }
            
            // 4. Подозрительные слова
            const foundKeywords = [];
            for (const keyword of this.suspiciousKeywords) {
                if (domain.includes(keyword)) {
                    foundKeywords.push(keyword);
                    results.risk_score += 15;
                }
            }
            results.checks.keywords = foundKeywords;
            
            if (foundKeywords.length > 0) {
                results.warnings.push({
                    text: `Обнаружены подозрительные слова: ${foundKeywords.join(', ')}`,
                    level: 'medium',
                    details: 'Используются в фишинговых атаках'
                });
            }
            
            // 5. IP-адрес в домене
            const ipRegex = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
            if (ipRegex.test(domain)) {
                results.warnings.push({
                    text: 'В домене используется IP-адрес',
                    level: 'medium',
                    details: 'Вместо доменного имени'
                });
                results.risk_score += 30;
            }
            
            // 6. Дефисы
            const dashCount = (domain.match(/-/g) || []).length;
            if (dashCount > 3) {
                results.warnings.push({
                    text: 'Слишком много дефисов в домене',
                    level: 'low',
                    details: `Найдено: ${dashCount} дефисов`
                });
                results.risk_score += 10;
            }
            
            // 7. Поддомены (слишком много)
            const subdomainCount = (domain.match(/\./g) || []).length;
            if (subdomainCount > 3) {
                results.warnings.push({
                    text: 'Слишком много поддоменов',
                    level: 'low',
                    details: `Найдено: ${subdomainCount} уровней`
                });
                results.risk_score += 5;
            }
            
            // Определяем уровень риска
            if (results.risk_score >= 60) {
                results.risk_level = 'high';
            } else if (results.risk_score >= 30) {
                results.risk_level = 'medium';
            } else {
                results.risk_level = 'low';
            }
            
        } catch (error) {
            results.error = error.message;
            results.risk_level = 'low';
        }
        
        return results;
    }
}

// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', function() {
    const scanner = new FishScanner();
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanBtn');
    const resultsSection = document.getElementById('results');
    const newScanBtn = document.getElementById('newScanBtn');
    const copyBtn = document.getElementById('copyBtn');
    const disclaimerBtn = document.getElementById('disclaimerBtn');
    
    // Примеры URL
    document.querySelectorAll('.tag').forEach(tag => {
        tag.addEventListener('click', function() {
            urlInput.value = this.dataset.url;
            urlInput.focus();
        });
    });
    
    // Автоматический формат URL
    urlInput.addEventListener('blur', function() {
        let url = urlInput.value.trim();
        if (url && !url.startsWith('http://') && !url.startsWith('https://')) {
            urlInput.value = 'https://' + url;
        }
    });
    
    // Сканирование
    scanBtn.addEventListener('click', async function() {
        let url = urlInput.value.trim();
        
        if (!url) {
            showError('Введите URL для проверки');
            urlInput.focus();
            return;
        }
        
        // Автодобавление протокола
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
            urlInput.value = url;
        }
        
        // Валидация
        if (!isValidURL(url)) {
            showError('Некорректный URL. Пример: https://example.com');
            return;
        }
        
        // Показать загрузку
        setLoading(true);
        
        try {
            const results = await scanner.scan(url);
            displayResults(results);
        } catch (error) {
            showError('Ошибка при сканировании: ' + error.message);
        } finally {
            setLoading(false);
        }
    });
    
    // Enter для запуска сканирования
    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            scanBtn.click();
        }
    });
    
    // Новая проверка
    newScanBtn.addEventListener('click', function() {
        resultsSection.classList.add('hidden');
        urlInput.value = '';
        urlInput.focus();
    });
    
    // Копировать отчет
    copyBtn.addEventListener('click', function() {
        const report = generateReport();
        navigator.clipboard.writeText(report)
            .then(() => showMessage('Отчет скопирован в буфер обмена!', 'success'))
            .catch(() => showError('Не удалось скопировать отчет'));
    });
    
    // Disclaimer
    if (disclaimerBtn) {
        disclaimerBtn.addEventListener('click', function(e) {
            e.preventDefault();
            alert(`🐟 FishScan - Отказ от ответственности\n\n` +
                  `Этот инструмент предназначен только для образовательных целей.\n` +
                  `Разработано: @lox-clou\n` +
                  `Не является заменой профессионального антивируса.\n` +
                  `Результаты не гарантируют 100% точность.\n\n` +
                  `Используйте на свой страх и риск.`);
        });
    }
    
    // Функции помощники
    function isValidURL(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }
    
    function setLoading(isLoading) {
        const btnText = scanBtn.querySelector('.btn-text');
        const spinner = scanBtn.querySelector('.spinner');
        
        scanBtn.disabled = isLoading;
        
        if (isLoading) {
            btnText.style.display = 'none';
            spinner.style.display = 'inline';
        } else {
            btnText.style.display = 'inline';
            spinner.style.display = 'none';
        }
    }
    
    function showError(message) {
        showMessage(message, 'error');
    }
    
    function showMessage(message, type = 'info') {
        // Создаем временное уведомление
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem 1.5rem;
            border-radius: 8px;
            background: ${type === 'error' ? '#fee' : '#dfd'};
            color: ${type === 'error' ? '#c00' : '#080'};
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 1000;
            animation: slideIn 0.3s ease;
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }
    
    // Отображение результатов
    function displayResults(data) {
        // Показываем секцию результатов
        resultsSection.classList.remove('hidden');
        
        // Домен
        document.getElementById('domainResult').textContent = data.domain;
        
        // Безопасность
        const securityEl = document.getElementById('securityResult');
        if (data.checks.https) {
            securityEl.textContent = '✅ HTTPS (безопасно)';
            securityEl.className = 'result-value text-success';
        } else {
            securityEl.textContent = '❌ HTTP (небезопасно)';
            securityEl.className = 'result-value text-danger';
        }
        
        // Статус (имитация)
        const ageEl = document.getElementById('ageResult');
        if (data.risk_level === 'high') {
            ageEl.textContent = '🚨 Высокий риск';
            ageEl.className = 'result-value text-danger';
        } else if (data.risk_level === 'medium') {
            ageEl.textContent = '⚠️ Средний риск';
            ageEl.className = 'result-value text-warning';
        } else {
            ageEl.textContent = '✅ Низкий риск';
            ageEl.className = 'result-value text-success';
        }
        
        // Риски
        const risksEl = document.getElementById('risksResult');
        risksEl.textContent = `${data.warnings.length} предупреждений`;
        risksEl.className = `result-value ${data.risk_level === 'high' ? 'text-danger' : 
                           data.risk_level === 'medium' ? 'text-warning' : 'text-success'}`;
        
        // Бейдж риска
        const riskBadge = document.getElementById('riskBadge');
        riskBadge.className = `risk-badge risk-${data.risk_level}`;
        
        let riskText;
        switch(data.risk_level) {
            case 'high':
                riskText = '🚨 Высокий риск';
                break;
            case 'medium':
                riskText = '⚠️ Средний риск';
                break;
            default:
                riskText = '✅ Низкий риск';
        }
        
        riskBadge.querySelector('.risk-text').textContent = riskText;
        
        // Предупреждения
        const warningsList = document.getElementById('warningsList');
        warningsList.innerHTML = '';
        
        if (data.warnings && data.warnings.length > 0) {
            data.warnings.forEach(warning => {
                const item = document.createElement('div');
                item.className = `warning-item ${warning.level === 'high' ? 'danger' : ''}`;
                item.innerHTML = `
                    <div class="warning-icon">${warning.level === 'high' ? '🚨' : '⚠️'}</div>
                    <div>
                        <strong>${warning.text}</strong>
                        ${warning.details ? `<br><small>${warning.details}</small>` : ''}
                    </div>
                `;
                warningsList.appendChild(item);
            });
        } else {
            const item = document.createElement('div');
            item.className = 'warning-item';
            item.innerHTML = `
                <div class="warning-icon">✅</div>
                <div>
                    <strong>Явных признаков фишинга не обнаружено</strong>
                    <br><small>Однако всегда оставайтесь внимательными</small>
                </div>
            `;
            warningsList.appendChild(item);
        }
        
        // Прокрутка к результатам
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }
    
    // Генерация отчета
    function generateReport() {
        const domain = document.getElementById('domainResult').textContent;
        const risk = document.getElementById('riskBadge').querySelector('.risk-text').textContent;
        const warnings = Array.from(document.querySelectorAll('.warning-item'))
            .map(item => {
                const text = item.querySelector('strong').textContent;
                const details = item.querySelector('small')?.textContent || '';
                return `• ${text}${details ? ` (${details})` : ''}`;
            })
            .join('\n');
        
        return `🐟 FishScan - Отчет проверки\n` +
               `===========================\n` +
               `URL: ${domain}\n` +
               `Уровень риска: ${risk}\n` +
               `Время проверки: ${new Date().toLocaleString('ru-RU')}\n` +
               `\n` +
               `ПРЕДУПРЕЖДЕНИЯ:\n` +
               `${warnings || '• Нет предупреждений'}\n` +
               `\n` +
               `⚠️ ВАЖНО:\n` +
               `• Этот отчет сгенерирован автоматически\n` +
               `• Не является гарантией безопасности\n` +
               `• Всегда проверяйте сайты вручную\n` +
               `• Разработано: @lox-clou\n` +
               `• GitHub: https://github.com/lox-clou/fishscan`;
    }
    
    // Добавляем стили для анимаций
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
    `;
    document.head.appendChild(style);
});
