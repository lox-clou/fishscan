document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanBtn');
    const resultsDiv = document.getElementById('results');
    const examples = document.querySelectorAll('.url-example');
    
    // Клик на примеры
    examples.forEach(example => {
        example.addEventListener('click', function() {
            urlInput.value = this.textContent;
        });
    });
    
    // Кнопка сканирования
    scanBtn.addEventListener('click', scanURL);
    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') scanURL();
    });
    
    // Кнопка новой проверки
    document.getElementById('newScanBtn').addEventListener('click', function() {
        resultsDiv.classList.add('hidden');
        urlInput.value = '';
        urlInput.focus();
    });
    
    // Кнопка репорта
    document.getElementById('reportBtn').addEventListener('click', function() {
        alert('Для сообщения о фишинге:\n1. Google Safe Browsing\n2. PhishTank\n3. CERT вашей страны');
    });
    
    // Дислеймер
    document.getElementById('disclaimerLink').addEventListener('click', function(e) {
        e.preventDefault();
        alert('DISCLAIMER:\n\nЭтот инструмент предоставляется "как есть".\nНе для проверки чужих сайтов без разрешения.\nНе для незаконной деятельности.\nТочность не гарантируется.');
    });
    
    // Функция сканирования
    async function scanURL() {
        const url = urlInput.value.trim();
        
        if (!url) {
            alert('Введите URL для проверки');
            return;
        }
        
        if (!isValidURL(url)) {
            alert('Неверный формат URL. Пример: https://example.com');
            return;
        }
        
        // Показываем загрузку
        scanBtn.textContent = 'Сканируем...';
        scanBtn.disabled = true;
        
        try {
            const response = await fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url })
            });
            
            const data = await response.json();
            displayResults(data);
            
        } catch (error) {
            console.error('Error:', error);
            alert('Ошибка при сканировании. Проверьте консоль.');
        } finally {
            scanBtn.textContent = 'Проверить';
            scanBtn.disabled = false;
        }
    }
    
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
        
        // Обновляем данные
        document.getElementById('domainResult').textContent = data.domain || '—';
        document.getElementById('sslResult').textContent = data.ssl ? '✅ HTTPS' : '❌ HTTP';
        document.getElementById('sslResult').className = data.ssl ? 'check-value good' : 'check-value bad';
        
        document.getElementById('ageResult').textContent = data.domain_age ? 
            `${data.domain_age} дней` : 'Неизвестно';
        document.getElementById('ageResult').className = 
            (data.domain_age > 30) ? 'check-value good' : 'check-value bad';
        
        document.getElementById('keywordsResult').textContent = data.suspicious_keywords?.length > 0 ?
            `Найдено: ${data.suspicious_keywords.length}` : 'Не найдено';
        
        // Бейдж риска
        const riskBadge = document.getElementById('riskBadge');
        riskBadge.textContent = getRiskLevel(data.risk_score);
        riskBadge.className = getRiskClass(data.risk_score);
        
        // Предупреждения
        const warningsBox = document.getElementById('warnings');
        const warningsList = document.getElementById('warningsList');
        
        if (data.warnings && data.warnings.length > 0) {
            warningsBox.classList.remove('hidden');
            warningsList.innerHTML = data.warnings.map(w => `<li>${w}</li>`).join('');
        } else {
            warningsBox.classList.add('hidden');
        }
        
        // Прокрутка к результатам
        resultsDiv.scrollIntoView({ behavior: 'smooth' });
    }
    
    // Уровень риска
    function getRiskLevel(score) {
        if (score < 20) return 'Низкий риск';
        if (score < 50) return 'Средний риск';
        return 'Высокий риск';
    }
    
    function getRiskClass(score) {
        if (score < 20) return 'risk-low';
        if (score < 50) return 'risk-medium';
        return 'risk-high';
    }
});
