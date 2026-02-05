/**
 * FishScan 2.0 - Продвинутый антифишинг сканер
 * Создано: @lox-clou
 */

class FishScanAI {
    constructor() {
        // API ключи
        this.apis = {
            virusTotal: '16112d8e1528f17860aa536cccb780e9e43f90ea9ebee80f2c8e6fdd4ba91bb9',
            urlScan: '019c2976-38e9-71b3-a03d-1f52ebff6081'
        };
        
        // База угроз в localStorage
        this.threatsDB = new ThreatDatabase();
        this.historyDB = new ScanHistory();
        this.settings = new SettingsManager();
        
        // AI модель (упрощённая)
        this.aiModel = {
            phishingPatterns: this.loadAIPatterns(),
            riskWeights: this.calculateRiskWeights()
        };
        
        // Состояние приложения
        this.state = {
            currentMode: 'fast',
            isScanning: false,
            activeTab: 'scanner',
            theme: 'light',
            notifications: []
        };
        
        // Инициализация
        this.init();
    }
    
    init() {
        this.loadState();
        this.setupEventListeners();
        this.updateUI();
        this.loadSampleData();
        this.startBackgroundTasks();
    }
    
    // ========== ОСНОВНЫЕ ФУНКЦИИ ==========
    
    async scanURL(url, mode = 'fast') {
        if (this.state.isScanning) return;
        
        this.state.isScanning = true;
        this.updateUI();
        
        try {
            const scanId = Date.now();
            const scanData = {
                id: scanId,
                url: url,
                mode: mode,
                timestamp: new Date().toISOString(),
                status: 'processing'
            };
            
            // Добавляем в историю
            this.historyDB.add(scanData);
            
            // Выполняем проверку
            const results = await this.performScan(url, mode);
            
            // Обновляем историю
            scanData.results = results;
            scanData.status = 'completed';
            this.historyDB.update(scanId, scanData);
            
            // Показываем результаты
            this.displayResults(results);
            
            // Проверяем на угрозы
            if (results.riskScore >= 50) {
                this.threatsDB.addThreat({
                    domain: results.domain,
                    type: 'phishing',
                    risk: results.riskLevel,
                    firstSeen: new Date().toISOString(),
                    lastSeen: new Date().toISOString()
                });
                
                this.sendNotification('Обнаружена угроза!', `${results.domain} - ${results.riskLevel} риск`);
            }
            
            return results;
            
        } catch (error) {
            console.error('Scan error:', error);
            this.sendNotification('Ошибка сканирования', error.message, 'error');
            return null;
        } finally {
            this.state.isScanning = false;
            this.updateUI();
        }
    }
    
    async performScan(url, mode) {
        const results = {
            url: url,
            domain: this.extractDomain(url),
            timestamp: new Date().toISOString(),
            checks: [],
            riskScore: 0,
            riskLevel: 'safe',
            aiAnalysis: null
        };
        
        // 1. Базовые проверки
        results.checks.push(...await this.basicChecks(url));
        
        // 2. Проверки в зависимости от режима
        if (mode === 'deep' || mode === 'ai') {
            results.checks.push(...await this.deepChecks(url));
        }
        
        // 3. AI анализ
        if (mode === 'ai') {
            results.aiAnalysis = await this.aiAnalyze(url, results.checks);
        }
        
        // 4. Проверка по внешним API
        if (this.settings.get('useExternalApis')) {
            results.externalChecks = await this.externalApiChecks(url);
        }
        
        // 5. Рассчитываем риск
        results.riskScore = this.calculateRiskScore(results.checks, results.aiAnalysis);
        results.riskLevel = this.getRiskLevel(results.riskScore);
        
        // 6. Генерация рекомендаций
        results.recommendations = this.generateRecommendations(results);
        
        return results;
    }
    
    // ========== ПРОВЕРКИ ==========
    
    async basicChecks(url) {
        const checks = [];
        const domain = this.extractDomain(url);
        
        // 1. Проверка HTTPS
        checks.push({
            type: 'security',
            name: 'HTTPS проверка',
            description: url.startsWith('https://') ? 
                'Сайт использует защищённое соединение' : 
                'Сайт использует незащищённый HTTP',
            status: url.startsWith('https://') ? 'safe' : 'danger',
            score: url.startsWith('https://') ? 0 : 30
        });
        
        // 2. Длина домена
        if (domain.length > 50) {
            checks.push({
                type: 'suspicious',
                name: 'Длина домена',
                description: `Домен слишком длинный (${domain.length} символов)`,
                status: 'warning',
                score: 10
            });
        }
        
        // 3. Имитация брендов
        const brandMatch = this.checkBrandImitation(domain);
        if (brandMatch) {
            checks.push({
                type: 'phishing',
                name: 'Имитация бренда',
                description: `Домен похож на ${brandMatch}`,
                status: 'danger',
                score: 40
            });
        }
        
        // 4. Подозрительные слова
        const suspiciousWords = this.findSuspiciousWords(domain);
        if (suspiciousWords.length > 0) {
            checks.push({
                type: 'suspicious',
                name: 'Подозрительные слова',
                description: `Найдены: ${suspiciousWords.join(', ')}`,
                status: 'warning',
                score: suspiciousWords.length * 5
            });
        }
        
        // 5. IP вместо домена
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain)) {
            checks.push({
                type: 'suspicious',
                name: 'IP-адрес',
                description: 'Используется IP вместо домена',
                status: 'warning',
                score: 20
            });
        }
        
        return checks;
    }
    
    async deepChecks(url) {
        const checks = [];
        const domain = this.extractDomain(url);
        
        // 1. Проверка SSL сертификата
        try {
            const sslInfo = await this.checkSSLCertificate(url);
            checks.push({
                type: 'security',
                name: 'SSL сертификат',
                description: sslInfo.valid ? 
                    `Сертификат действителен до ${sslInfo.expires}` : 
                    'Проблемы с SSL сертификатом',
                status: sslInfo.valid ? 'safe' : 'danger',
                score: sslInfo.valid ? 0 : 25
            });
        } catch (error) {
            // Пропускаем если не удалось проверить
        }
        
        // 2. Проверка DNS записей
        try {
            const dnsInfo = await this.checkDNSRecords(domain);
            checks.push({
                type: 'technical',
                name: 'DNS записи',
                description: `Найдено ${dnsInfo.records.length} записей`,
                status: 'info',
                score: 0
            });
        } catch (error) {
            // Пропускаем
        }
        
        // 3. Проверка WHOIS
        if (this.settings.get('checkWhois')) {
            try {
                const whoisInfo = await this.checkWHOIS(domain);
                const domainAge = this.calculateDomainAge(whoisInfo.creationDate);
                
                if (domainAge < 30) {
                    checks.push({
                        type: 'suspicious',
                        name: 'Возраст домена',
                        description: `Домен создан ${domainAge} дней назад`,
                        status: 'warning',
                        score: 15
                    });
                }
            } catch (error) {
                // Пропускаем
            }
        }
        
        // 4. Проверка в базе угроз
        const threatCheck = this.threatsDB.checkDomain(domain);
        if (threatCheck.found) {
            checks.push({
                type: 'threat',
                name: 'В базе угроз',
                description: `Обнаружен ${threatCheck.times} раз(а)`,
                status: 'danger',
                score: 50
            });
        }
        
        return checks;
    }
    
    async aiAnalyze(url, checks) {
        // Упрощённый AI анализ
        const domain = this.extractDomain(url);
        
        // Анализ паттернов
        const patterns = this.aiModel.phishingPatterns;
        let aiScore = 0;
        const detectedPatterns = [];
        
        // Проверка на фишинг паттерны
        for (const pattern of patterns) {
            if (pattern.test(domain)) {
                aiScore += pattern.weight;
                detectedPatterns.push(pattern.name);
            }
        }
        
        // Анализ структуры URL
        const urlStructure = this.analyzeURLStructure(url);
        aiScore += urlStructure.score;
        
        // Машинное обучение (упрощённо)
        const mlPrediction = this.mlPredict(url, checks);
        aiScore += mlPrediction.score;
        
        return {
            score: aiScore,
            confidence: Math.min(100, aiScore),
            detectedPatterns: detectedPatterns,
            prediction: mlPrediction.prediction,
            explanation: this.generateAIExplanation(aiScore, detectedPatterns)
        };
    }
    
    async externalApiChecks(url) {
        const results = {};
        
        // VirusTotal
        if (this.apis.virusTotal && !this.apis.virusTotal.includes('YOUR_')) {
            try {
                results.virusTotal = await this.checkVirusTotalAPI(url);
            } catch (error) {
                console.warn('VirusTotal API error:', error);
            }
        }
        
        // URLScan.io
        if (this.apis.urlScan && !this.apis.urlScan.includes('YOUR_')) {
            try {
                results.urlScan = await this.checkURLScanAPI(url);
            } catch (error) {
                console.warn('URLScan API error:', error);
            }
        }
        
        // Google Safe Browsing (через прокси)
        try {
            results.safeBrowsing = await this.checkSafeBrowsing(url);
        } catch (error) {
            // Пропускаем
        }
        
        return results;
    }
    
    // ========== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ==========
    
    extractDomain(url) {
        try {
            let domain = url.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '');
            domain = domain.split('/')[0];
            domain = domain.split('?')[0];
            return domain;
        } catch {
            return url;
        }
    }
    
    checkBrandImitation(domain) {
        const brands = [
            { name: 'google', domains: ['google.com', 'gmail.com'] },
            { name: 'facebook', domains: ['facebook.com', 'fb.com'] },
            { name: 'apple', domains: ['apple.com', 'icloud.com'] },
            { name: 'microsoft', domains: ['microsoft.com', 'outlook.com'] },
            { name: 'paypal', domains: ['paypal.com'] },
            { name: 'github', domains: ['github.com'] },
            { name: 'twitter', domains: ['twitter.com', 'x.com'] }
        ];
        
        for (const brand of brands) {
            for (const brandDomain of brand.domains) {
                // Простая проверка схожести
                if (this.calculateSimilarity(domain, brandDomain) > 0.7 && domain !== brandDomain) {
                    return brand.name;
                }
                
                // Проверка замены букв (faceb00k -> facebook)
                const normalizedDomain = domain
                    .replace(/0/g, 'o')
                    .replace(/1/g, 'i')
                    .replace(/3/g, 'e')
                    .replace(/4/g, 'a')
                    .replace(/5/g, 's');
                
                if (normalizedDomain.includes(brandDomain.replace('.com', ''))) {
                    return brand.name;
                }
            }
        }
        
        return null;
    }
    
    findSuspiciousWords(text) {
        const words = [
            'login', 'verify', 'secure', 'account', 'bank', 'pay', 'wallet',
            'crypto', 'bitcoin', 'password', 'update', 'confirm', 'validation',
            'authenticate', 'signin', 'signup', 'official', 'support', 'help',
            'customer', 'service', 'security', 'alert', 'warning', 'urgent'
        ];
        
        return words.filter(word => text.toLowerCase().includes(word));
    }
    
    calculateSimilarity(str1, str2) {
        // Упрощённый алгоритм Левенштейна
        const longer = str1.length > str2.length ? str1 : str2;
        const shorter = str1.length > str2.length ? str2 : str1;
        
        if (longer.length === 0) return 1.0;
        
        // Расстояние Левенштейна
        const distance = this.levenshteinDistance(longer, shorter);
        return (longer.length - distance) / longer.length;
    }
    
    levenshteinDistance(a, b) {
        const matrix = Array(b.length + 1).fill().map(() => Array(a.length + 1).fill(0));
        
        for (let i = 0; i <= a.length; i++) matrix[0][i] = i;
        for (let j = 0; j <= b.length; j++) matrix[j][0] = j;
        
        for (let j = 1; j <= b.length; j++) {
            for (let i = 1; i <= a.length; i++) {
                const cost = a[i - 1] === b[j - 1] ? 0 : 1;
                matrix[j][i] = Math.min(
                    matrix[j][i - 1] + 1,
                    matrix[j - 1][i] + 1,
                    matrix[j - 1][i - 1] + cost
                );
            }
        }
        
        return matrix[b.length][a.length];
    }
    
    calculateRiskScore(checks, aiAnalysis) {
        let score = 0;
        
        // Суммируем баллы проверок
        for (const check of checks) {
            score += check.score || 0;
        }
        
        // Добавляем AI анализ
        if (aiAnalysis) {
            score += aiAnalysis.score * 0.5; // Вес AI анализа
        }
        
        // Нормализуем до 100
        return Math.min(100, Math.max(0, score));
    }
    
    getRiskLevel(score) {
        if (score >= 80) return 'critical';
        if (score >= 60) return 'high';
        if (score >= 40) return 'medium';
        if (score >= 20) return 'low';
        return 'safe';
    }
    
    generateRecommendations(results) {
        const recommendations = [];
        
        if (results.riskLevel === 'critical' || results.riskLevel === 'high') {
            recommendations.push('🚨 НЕМЕДЛЕННО ПРЕКРАТИТЕ ИСПОЛЬЗОВАНИЕ САЙТА!');
            recommendations.push('🔒 Никогда не вводите пароли, данные карт или личную информацию');
            recommendations.push('📧 Сообщите о фишинге в соответствующие органы');
        }
        
        if (results.checks.some(c => c.type === 'security' && c.status === 'danger')) {
            recommendations.push('🔐 Сайт не использует HTTPS - данные могут быть перехвачены');
        }
        
        if (results.checks.some(c => c.type === 'phishing')) {
            recommendations.push('🎭 Обнаружена возможная имитация известного бренда');
        }
        
        if (results.riskLevel === 'medium') {
            recommendations.push('⚠️ Будьте осторожны при использовании этого сайта');
            recommendations.push('👁️ Проверьте адресную строку перед вводом данных');
        }
        
        if (results.riskLevel === 'safe') {
            recommendations.push('✅ Сайт выглядит безопасным');
            recommendations.push('🔍 Но всегда оставайтесь бдительными');
        }
        
        // AI рекомендации
        if (results.aiAnalysis && results.aiAnalysis.confidence > 70) {
            recommendations.push(`🤖 AI анализ: ${results.aiAnalysis.explanation}`);
        }
        
        return recommendations;
    }
    
    // ========== API МЕТОДЫ ==========
    
    async checkVirusTotalAPI(url) {
        const encodedUrl = btoa(url).replace(/=/g, '');
        const response = await fetch(`https://www.virustotal.com/api/v3/urls/${encodedUrl}`, {
            headers: { 'x-apikey': this.apis.virusTotal }
        });
        
        if (!response.ok) throw new Error('VirusTotal API error');
        return await response.json();
    }
    
    async checkURLScanAPI(url) {
        // Отправляем на сканирование
        const scanResponse = await fetch('https://urlscan.io/api/v1/scan/', {
            method: 'POST',
            headers: {
                'API-Key': this.apis.urlScan,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url, visibility: 'public' })
        });
        
        if (!scanResponse.ok) throw new Error('URLScan API error');
        const scanData = await scanResponse.json();
        
        // Ждём результаты
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        const resultResponse = await fetch(`https://urlscan.io/api/v1/result/${scanData.uuid}/`);
        if (!resultResponse.ok) throw new Error('URLScan result error');
        
        return await resultResponse.json();
    }
    
    async checkSafeBrowsing(url) {
        // Используем публичный прокси для Google Safe Browsing
        const encodedUrl = encodeURIComponent(url);
        const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${this.apis.googleSafe}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                client: { clientId: "fishscan", clientVersion: "2.0" },
                threatInfo: {
                    threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: [{ url: url }]
                }
            })
        });
        
        if (!response.ok) return { safe: true }; // Если API не доступен, считаем безопасным
        
        const data = await response.json();
        return {
            safe: !data.matches || data.matches.length === 0,
            matches: data.matches || []
        };
    }
    
    // ========== UI МЕТОДЫ ==========
    
    displayResults(results) {
        // Создаём HTML для результатов
        const html = this.generateResultsHTML(results);
        
        // Вставляем в панель результатов
        const resultsPanel = document.getElementById('resultsPanel');
        const resultsContent = resultsPanel.querySelector('.results-content');
        resultsContent.innerHTML = html;
        
        // Показываем панель
        resultsPanel.classList.remove('hidden');
        
        // Обновляем график риска
        this.updateRiskChart(results.riskScore);
    }
    
    generateResultsHTML(results) {
        return `
            <div class="results-summary">
                <div class="risk-score-card ${results.riskLevel}">
                    <div class="risk-score">${Math.round(results.riskScore)}%</div>
                    <div class="risk-level">${this.getRiskLabel(results.riskLevel)}</div>
                </div>
                
                <div class="domain-info">
                    <h4>${results.domain}</h4>
                    <p>Проверено: ${new Date(results.timestamp).toLocaleString()}</p>
                </div>
            </div>
            
            <div class="checks-list">
                <h4>Проверки (${results.checks.length})</h4>
                ${results.checks.map(check => `
                    <div class="check-item ${check.status}">
                        <div class="check-icon">${this.getStatusIcon(check.status)}</div>
                        <div class="check-details">
                            <div class="check-name">${check.name}</div>
                            <div class="check-desc">${check.description}</div>
                        </div>
                        <div class="check-score">${check.score || 0}</div>
                    </div>
                `).join('')}
            </div>
            
            ${results.aiAnalysis ? `
                <div class="ai-analysis">
                    <h4>🤖 AI Анализ</h4>
                    <div class="ai-confidence">
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: ${results.aiAnalysis.confidence}%"></div>
                        </div>
                        <div class="confidence-text">Уверенность: ${Math.round(results.aiAnalysis.confidence)}%</div>
                    </div>
                    <p>${results.aiAnalysis.explanation}</p>
                </div>
            ` : ''}
            
            <div class="recommendations">
                <h4>🎯 Рекомендации</h4>
                <ul>
                    ${results.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                </ul>
            </div>
        `;
    }
    
    getRiskLabel(level) {
        const labels = {
            safe: '✅ Безопасно',
            low: '⚠️ Низкий риск',
            medium: '🚨 Средний риск',
            high: '🔥 Высокий риск',
            critical: '☢️ КРИТИЧЕСКИЙ РИСК'
        };
        return labels[level] || level;
    }
    
    getStatusIcon(status) {
        const icons = {
            safe: '✅',
            warning: '⚠️',
            danger: '❌',
            info: 'ℹ️'
        };
        return icons[status] || '🔍';
    }
    
    updateRiskChart(score) {
        const ctx = document.getElementById('riskChart')?.getContext('2d');
        if (!ctx) return;
        
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [score, 100 - score],
                    backgroundColor: [
                        this.getRiskColor(score),
                        '#e5e7eb'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                cutout: '70%',
                responsive: true,
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: false }
                }
            }
        });
    }
    
    getRiskColor(score) {
        if (score >= 80) return '#dc2626';
        if (score >= 60) return '#ef4444';
        if (score >= 40) return '#f59e0b';
        if (score >= 20) return '#fbbf24';
        return '#10b981';
    }
    
    // ========== УПРАВЛЕНИЕ СОСТОЯНИЕМ ==========
    
    loadState() {
        const savedState = localStorage.getItem('fishscan_state');
        if (savedState) {
            this.state = { ...this.state, ...JSON.parse(savedState) };
        }
        
        // Применяем тему
        document.documentElement.setAttribute('data-theme', this.state.theme);
    }
    
    saveState() {
        localStorage.setItem('fishscan_state', JSON.stringify(this.state));
    }
    
    updateUI() {
        // Обновляем активную вкладку
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.dataset.tab === this.state.activeTab);
        });
        
        document.querySelectorAll('.tab-pane').forEach(pane => {
            pane.classList.toggle('active', pane.id === `${this.state.activeTab}Tab`);
        });
        
        // Обновляем заголовок
        const titles = {
            scanner: 'Сканер фишинга',
            history: 'История проверок',
            threats: 'База угроз',
            api: 'API документация',
            settings: 'Настройки'
        };
        document.getElementById('pageTitle').textContent = titles[this.state.activeTab] || 'FishScan';
        
        // Обновляем статистику
        this.updateStats();
    }
    
    updateStats() {
        const history = this.historyDB.getAll();
        const threats = this.threatsDB.getCount();
        
        document.getElementById('historyCount').textContent = history.length;
        document.getElementById('threatsCount').textContent = threats;
        document.getElementById('miniScans').textContent = history.length;
        document.getElementById('miniThreats').textContent = threats;
    }
    
    setupEventListeners() {
        // Навигация
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                this.state.activeTab = item.dataset.tab;
                this.updateUI();
            });
        });
        
        // Сканирование
        document.getElementById('scanBtn').addEventListener('click', () => {
            const url = document.getElementById('urlInput').value.trim();
            if (url) this.scanURL(url, this.state.currentMode);
        });
        
        // Режимы сканирования
        document.querySelectorAll('.mode-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.state.currentMode = btn.dataset.mode;
            });
        });
        
        // Тёмная тема
        document.getElementById('darkModeToggle').addEventListener('click', () => {
            this.state.theme = this.state.theme === 'light' ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', this.state.theme);
            this.saveState();
        });
        
        // Примеры URL
        document.querySelectorAll('.dropdown-item').forEach(item => {
            item.addEventListener('click', () => {
                const url = item.dataset.url;
                document.getElementById('urlInput').value = url;
            });
        });
        
        // Быстрые действия
        document.getElementById('quickCheck').addEventListener('click', () => {
            document.getElementById('urlInput').focus();
        });
        
        document.getElementById('bulkCheck').addEventListener('click', () => {
            document.getElementById('bulkModal').classList.remove('hidden');
        });
        
        // Закрытие модальных окон
        document.querySelectorAll('.modal-close, .btn-close-preview, #closeResults').forEach(btn => {
            btn.addEventListener('click', () => {
                btn.closest('.modal, .preview-results, .results-panel').classList.add('hidden');
            });
        });
    }
    
    sendNotification(title, message, type = 'info') {
        const notification = {
            id: Date.now(),
            title: title,
            message: message,
            type: type,
            timestamp: new Date().toISOString(),
            read: false
        };
        
        this.state.notifications.unshift(notification);
        this.updateNotifications();
        
        // Автоматическое скрытие
        setTimeout(() => {
            const index = this.state.notifications.findIndex(n => n.id === notification.id);
            if (index !== -1) {
                this.state.notifications.splice(index, 1);
                this.updateNotifications();
            }
        }, 5000);
    }
    
    updateNotifications() {
        const container = document.querySelector('.notifications-list');
        if (!container) return;
        
        container.innerHTML = this.state.notifications.map(notif => `
            <div class="notification-item ${notif.type} ${notif.read ? 'read' : 'unread'}">
                <div class="notification-icon">${this.getNotificationIcon(notif.type)}</div>
                <div class="notification-content">
                    <div class="notification-title">${notif.title}</div>
                    <div class="notification-message">${notif.message}</div>
                    <div class="notification-time">${new Date(notif.timestamp).toLocaleTimeString()}</div>
                </div>
                <button class="notification-close" data-id="${notif.id}">×</button>
            </div>
        `).join('');
        
        // Обновляем бейдж
        const unread = this.state.notifications.filter(n => !n.read).length;
        const badge = document.querySelector('.notification-badge');
        if (badge) {
            badge.textContent = unread;
            badge.style.display = unread > 0 ? 'flex' : 'none';
        }
    }
    
    getNotificationIcon(type) {
        const icons = {
            info: 'ℹ️',
            success: '✅',
            warning: '⚠️',
            error: '❌'
        };
        return icons[type] || '📢';
    }
    
    loadSampleData() {
        // Загружаем демо данные если история пуста
        if (this.historyDB.getAll().length === 0) {
            const sampleScans = [
                {
                    url: 'https://github.com',
                    results: { riskScore: 5, riskLevel: 'safe' },
                    timestamp: new Date(Date.now() - 300000).toISOString()
                },
                {
                    url: 'http://secure-bank-login.ru',
                    results: { riskScore: 75, riskLevel: 'high' },
                    timestamp: new Date(Date.now() - 600000).toISOString()
                }
            ];
            
            sampleScans.forEach(scan => this.historyDB.add(scan));
            this.updateStats();
        }
    }
    
    startBackgroundTasks() {
        // Фоновое обновление базы угроз
        setInterval(() => {
            this.threatsDB.syncWithCloud();
        }, 300000); // Каждые 5 минут
        
        // Проверка новых уведомлений
        setInterval(() => {
            this.checkForNewThreats();
        }, 60000); // Каждую минуту
    }
    
    checkForNewThreats() {
        // Здесь можно добавить проверку новых угроз из внешних источников
        // Например, подписка на RSS фид или API
    }
}

// ========== ВСПОМОГАТЕЛЬНЫЕ КЛАССЫ ==========

class ThreatDatabase {
    constructor() {
        this.dbName = 'fishscan_threats';
        this.load();
    }
    
    load() {
        const data = localStorage.getItem(this.dbName);
        this.threats = data ? JSON.parse(data) : [];
    }
    
    save() {
        localStorage.setItem(this.dbName, JSON.stringify(this.threats));
    }
    
    addThreat(threat) {
        const existing = this.threats.find(t => t.domain === threat.domain);
        
        if (existing) {
            existing.lastSeen = threat.lastSeen;
            existing.count = (existing.count || 1) + 1;
        } else {
            threat.count = 1;
            this.threats.push(threat);
        }
        
        this.save();
        return true;
    }
    
    checkDomain(domain) {
        const threats = this.threats.filter(t => t.domain === domain);
        return {
            found: threats.length > 0,
            count: threats.length,
            threats: threats
        };
    }
    
    getCount() {
        return this.threats.length;
    }
    
    getAll() {
        return [...this.threats];
    }
    
    syncWithCloud() {
        // Здесь можно добавить синхронизацию с облачной базой
        console.log('Синхронизация базы угроз...');
    }
}

class ScanHistory {
    constructor() {
        this.dbName = 'fishscan_history';
        this.maxItems = 1000;
        this.load();
    }
    
    load() {
        const data = localStorage.getItem(this.dbName);
        this.history = data ? JSON.parse(data) : [];
    }
    
    save() {
        // Сохраняем только последние maxItems записей
        if (this.history.length > this.maxItems) {
            this.history = this.history.slice(-this.maxItems);
        }
        localStorage.setItem(this.dbName, JSON.stringify(this.history));
    }
    
    add(scan) {
        this.history.push({
            ...scan,
            id: scan.id || Date.now(),
            timestamp: scan.timestamp || new Date().toISOString()
        });
        this.save();
    }
    
    update(id, data) {
        const index = this.history.findIndex(item => item.id === id);
        if (index !== -1) {
            this.history[index] = { ...this.history[index], ...data };
            this.save();
        }
    }
    
    getAll() {
        return [...this.history].reverse(); // Новые сверху
    }
    
    clear() {
        this.history = [];
        this.save();
    }
}

class SettingsManager {
    constructor() {
        this.defaults = {
            useExternalApis: true,
            checkWhois: true,
            checkSsl: true,
            useAi: true,
            theme: 'light',
            notifications: true
        };
        this.load();
    }
    
    load() {
        const data = localStorage.getItem('fishscan_settings');
        this.settings = data ? { ...this.defaults, ...JSON.parse(data) } : { ...this.defaults };
    }
    
    save() {
        localStorage.setItem('fishscan_settings', JSON.stringify(this.settings));
    }
    
    get(key) {
        return this.settings[key] ?? this.defaults[key];
    }
    
    set(key, value) {
        this.settings[key] = value;
        this.save();
    }
}

// ========== ИНИЦИАЛИЗАЦИЯ ==========

document.addEventListener('DOMContentLoaded', () => {
    // Создаём экземпляр сканера
    window.fishScan = new FishScanAI();
    
    // Дополнительные обработчики событий
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanBtn');
    
    // Enter для сканирования
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && urlInput.value.trim()) {
            scanBtn.click();
        }
    });
    
    // Автодополнение протокола
    urlInput.addEventListener('blur', function() {
        let url = this.value.trim();
        if (url && !url.startsWith('http://') && !url.startsWith('https://') && url.includes('.')) {
            this.value = 'https://' + url;
        }
    });
    
    // Вставить из буфера
    document.getElementById('pasteBtn').addEventListener('click', async () => {
        try {
            const text = await navigator.clipboard.readText();
            if (text) {
                urlInput.value = text;
                urlInput.focus();
                
                // Показываем предпросмотр
                document.getElementById('previewResults').classList.remove('hidden');
            }
        } catch (error) {
            console.warn('Не удалось вставить из буфера:', error);
        }
    });
    
    // Очистить поле
    document.getElementById('clearBtn').addEventListener('click', () => {
        urlInput.value = '';
        urlInput.focus();
        document.getElementById('previewResults').classList.add('hidden');
    });
    
    // Уведомления
    document.getElementById('notificationsBtn').addEventListener('click', () => {
        document.getElementById('notificationsContainer').classList.toggle('show');
    });
    
    document.getElementById('closeNotifications').addEventListener('click', () => {
        document.getElementById('notificationsContainer').classList.remove('show');
    });
    
    // Полный экран
    document.getElementById('fullscreenBtn').addEventListener('click', () => {
        if (!document.fullscreenElement) {
            document.documentElement.requestFullscreen();
        } else {
            document.exitFullscreen();
        }
    });
    
    // Закрытие модальных окон по клику вне
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.classList.add('hidden');
            }
        });
    });
});
