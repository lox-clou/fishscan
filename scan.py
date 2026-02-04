from flask import Flask, request, jsonify, send_from_directory
import re
import whois
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
import requests
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

class URLScanner:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'verify', 'secure', 'account', 'banking',
            'update', 'confirm', 'password', 'wallet', 'crypto',
            'paypal', 'facebook', 'google', 'microsoft'
        ]
        
        self.legit_domains = [
            'google.com', 'facebook.com', 'github.com', 'microsoft.com',
            'apple.com', 'amazon.com', 'paypal.com', 'steamcommunity.com'
        ]
    
    def scan(self, url):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            results = {
                'url': url,
                'domain': domain,
                'risk_score': 0,
                'warnings': [],
                'ssl': False,
                'domain_age': None,
                'suspicious_keywords': []
            }
            
            # Проверка SSL
            results['ssl'] = parsed.scheme == 'https'
            if not results['ssl']:
                results['warnings'].append('Сайт использует HTTP вместо HTTPS')
                results['risk_score'] += 20
            
            # Проверка похожести домена
            for legit in self.legit_domains:
                if legit in domain and domain != legit:
                    results['warnings'].append(f'Домен похож на {legit}')
                    results['risk_score'] += 30
            
            # Проверка подозрительных слов в домене
            for keyword in self.suspicious_keywords:
                if keyword in domain:
                    results['suspicious_keywords'].append(keyword)
                    results['risk_score'] += 10
            
            # Проверка IP в домене
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                results['warnings'].append('В домене используется IP-адрес')
                results['risk_score'] += 15
            
            # Возраст домена
            try:
                domain_info = whois.whois(domain)
                if domain_info.creation_date:
                    if isinstance(domain_info.creation_date, list):
                        creation_date = domain_info.creation_date[0]
                    else:
                        creation_date = domain_info.creation_date
                    
                    age_days = (datetime.now() - creation_date).days
                    results['domain_age'] = age_days
                    
                    if age_days < 30:
                        results['warnings'].append(f'Домен создан недавно ({age_days} дней)')
                        results['risk_score'] += 25
            except:
                results['warnings'].append('Не удалось проверить возраст домена')
                results['risk_score'] += 5
            
            return results
            
        except Exception as e:
            return {'error': str(e), 'url': url}

scanner = URLScanner()

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.json
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL не указан'}), 400
    
    # Простая валидация URL
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = 'http://' + url
    
    results = scanner.scan(url)
    return jsonify(results)

@app.route('/styles.css')
def styles():
    return send_from_directory('.', 'styles.css')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
