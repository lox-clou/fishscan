class PhishScanner {
    constructor() {
        this.suspiciousKeywords = [
            'login', 'verify', 'secure', 'account', 'banking',
            'update', 'confirm', 'password', 'wallet', 'crypto',
            'paypal', 'facebook', 'google', 'microsoft', 'apple',
            'amazon', 'instagram', 'twitter', 'netflix', 'steam'
        ];
        
        this.legitDomains = [
            'google.com', 'facebook.com', 'github.com', 'microsoft.com',
            'apple.com', 'amazon.com', 'paypal.com', 'steamcommunity.com',
            'twitter.com', 'instagram.com', 'netflix.com'
        ];
    }
    
    scan(url) {
        return new Promise((resolve) => {
            setTimeout(() => {
                try {
                    const results = this._analyzeURL(url);
                    resolve(results);
                } catch (error) {
                    resolve({
                        error: 'Ошибка анализа URL',
                        risk_score: 0
                    });
                }
            }, 1500); // Имитация задержки
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
            results.domain = domain;
            
            // 1. Проверка HTTPS
            const hasHTTPS = url.startsWith('https://');
            results.checks.https = hasHTTPS;
            if (!hasHTTPS) {
                results.warnings.push('Сайт использует HTTP вместо HTTPS');
                results.risk_score += 20;
            }
            
            // 2. Проверка длины домена
            if (domain.length > 50) {
                results.warnings.push('Слишком длинное доменное имя');
                results.risk_score += 10;
            }
            
            // 3. Похожесть на бренды
            for (const legit of this.legitDomains) {
                if (domain.includes(legit) && domain !== legit) {
                    results.warnings.push(`Домен имитирует ${legit}`);
                    results.risk_score += 40;
                    results.is_phishing = true;
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
                results.warnings.push(`Обнаружены подозрительные слова: ${foundKeywords.join(', ')}`);
            }
            
            // 5. IP-адрес в домене
            const ipRegex = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
            if (ipRegex.test(domain)) {
                results.warnings.push('В домене используется IP-адрес');
                results.risk_score += 30;
            }
            
            // 6. Дефисы
            const dashCount = (domain.match(/-/g) || []).length;
            if (dashCount > 3) {
                results.warnings.push('Слишком много дефисов в домене');
                results.risk_score += 10;
            }
            
            // 7. Валидность TLD
            const validTLDs = ['.com', '.ru', '.org', '.net', '.io', '.xyz'];
            const hasValidTLD = validTLDs.some(tld => domain.endsWith(tld));
            if (!hasValidTLD) {
                results.warnings.push('Нестандартное окончание домена');
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
        }
        
        return results;
    }
}

// Инициализация
document.addEventListener('DOMContentLoaded', function() {
    const scanner = new PhishScanner();
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanBtn');
    const resultsDiv = document.getElementById('results');
    const newScanBtn = document.getElementById('newScanBtn');
    const copyBtn = document.getElementById('copyBtn');
    const disclaimerBtn = document.getElementById('disclaimerBtn');
    
    // Примеры URL
    document.querySelectorAll('.tag').forEach(tag => {
        tag.addEventListener('click', function() {
            urlInput.value = this.dataset.url;
        });
    });
    
    // Сканирование
    scanBtn.addEventListener('click', async function() {
        const url = urlInput.value.trim();
        
        if (!url) {
            alert('Введите URL для проверки');
            return;
        }
        
        // Валидация
        if (!isValidURL(url)) {
            alert('Некорректный URL. Пример: https://example.com');
            return;
        }
        
        // Показать загрузку
        scanBtn.disabled = true;
        scanBtn.querySelector('.btn-text').classList.add('hidden');
        scanBtn.querySelector('.spinner').classList.remove('hidden');
        
        // Сканировать
        const results = await scanner.scan(url);
        
        // Показать результаты
        displayResults(results);
        
        // Сбросить кнопку
        scanBtn.disabled = false;
        scanBtn.querySelector('.btn-text').classList.remove('hidden');
        scanBtn.querySelector('.spinner').classList.add('hidden');
    });
    
    // Новая проверка
    newScanBtn.addEventListener('click', function() {
        resultsDiv.classList.add('hidden');
        urlInput.value = '';
        urlInput.focus();
    });
    
    // Копировать отчет
    copyBtn.addEventListener('click', function() {
        const resultsText = generateReportText();
        navigator.clipboard.writeText(resultsText)
            .then(() => alert('Отчет скопирован в буфер обмена'))
            .catch(() => alert('Не удалось скопировать'));
    });
    
    // Disclaimer
    disclaimerBtn.addEventListener('click', function(e) {
        e.preventDefault();
        alert('⚠️ Disclaimer:\n\nЭтот инструмент предназначен только для образовательных целей.\nНе является заменой профессионального антивируса.\nАвтор не несет ответственности за результаты проверки.\n\nИспользуйте на свой страх и риск.');
    });
    
    // Валидация URL
    function isValidURL(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }
    
    // Отображение результатов
    function displayResults(data) {
        resultsDiv.classList.remove('hidden');
        
        // Домен
        document.getElementById('domainResult').textContent = data.domain;
        
        // Безопасность
        const securityEl = document.getElementById('securityResult');
        if (data.checks.https) {
            securityEl.textContent = '✅ HTTPS';
            securityEl.className = 'result-value text-success';
        } else {
            securityEl.textContent = '❌ HTTP (небезопасно)';
            securityEl.className = 'result-value text-danger';
        }
        
        // Возраст (имитация)
        const ageEl = document.getElementById('ageResult');
        ageEl.textContent = 'Не проверяется';
        ageEl.className = 'result-value text-warning';
        
        // Риски
        const risksEl = document.getElementById('risksResult');
        risksEl.textContent = `${data.warnings.length} предупреждений`;
        risksEl.className = `result-value ${data.risk_level === 'high' ? 'text-danger' : 
                           data.risk_level === 'medium' ? 'text-warning' : 'text-success'}`;
        
        // Бейдж риска
        const riskBadge = document.getElementById('riskBadge');
        riskBadge.className = `risk-badge risk-${data.risk_level}`;
        
        let riskText, riskColor;
        switch(data.risk_level) {
            case 'high':
                riskText = 'Высокий риск';
                riskColor = '#dc2626';
                break;
            case 'medium':
                riskText = 'Средний риск';
                riskColor = '#f59e0b';
                break;
            default:
                riskText = 'Низкий риск';
                riskColor = '#10b981';
        }
        
        riskBadge.querySelector('.risk-text').textContent = riskText;
        riskBadge.querySelector('.risk-dot').style.backgroundColor = riskColor;
        
        // Предупреждения
        const warningsList = document.getElementById('warningsList');
        warningsList.innerHTML = '';
        
        if (data.warnings.length > 0) {
            data.warnings.forEach(warning => {
                const item = document.createElement('div');
                item.className = `warning-item ${data.risk_level === 'high' ? 'danger' : ''}`;
                item.innerHTML = `
                    <div class="warning-icon">⚠️</div>
                    <div>${warning}</div>
                `;
                warningsList.appendChild(item);
            });
        } else {
            const item = document.createElement('div');
            item.className = 'warning-item';
            item.innerHTML = `
                <div class="warning-icon">✅</div>
                <div>Пока не обнаружено явных признаков фишинга</div>
            `;
            warningsList.appendChild(item);
        }
        
        // Прокрутка к результатам
        resultsDiv.scrollIntoView({ behavior: 'smooth' });
    }
    
    // Генерация отчета
    function generateReportText() {
        const domain = document.getElementById('domainResult').textContent;
        const risk = document.getElementById('riskBadge').querySelector('.risk-text').textContent;
        const warnings = Array.from(document.querySelectorAll('.warning-item'))
            .map(item => item.lastElementChild.textContent)
            .join('\n• ');
        
        return `Отчет PhishScan\n
URL: ${domain}
Уровень риска: ${risk}
Время проверки: ${new Date().toLocaleString()}

Предупреждения:
${warnings ? '• ' + warnings : 'Нет предупреждений'}

⚠️ Этот отчет сгенерирован автоматически.
Не является гарантией безопасности.`;
    }
});
