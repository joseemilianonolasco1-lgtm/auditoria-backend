import socket
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
# Permite que tu frontend consulte esta API
CORS(app) 

# Reemplaza con tu API Key (puedes usar Groq que tiene capa gratuita muy rápida)
AI_API_KEY = "TU_API_KEY_AQUI"
AI_API_URL = "https://api.groq.com/openai/v1/chat/completions"

def scan_ports(target_domain):
    open_ports = []
    ports_to_check = [21, 22, 23, 3306, 8080] # Puertos que jamás deberían estar públicos
    for port in ports_to_check:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_domain, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def check_security_headers(url):
    missing_headers = []
    try:
        if not url.startswith('http'):
            url = 'https://' + url
        response = requests.get(url, timeout=5)
        headers = response.headers
        security_headers = [
            'Strict-Transport-Security',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Content-Security-Policy'
        ]
        for header in security_headers:
            if header not in headers:
                missing_headers.append(header)
    except Exception as e:
        return ["Error_de_conexion"]
    return missing_headers

@app.route('/api/scan', methods=['POST'])
def run_scan():
    """FASE 1: El Gancho Gratuito (Requiere Consentimiento)"""
    data = request.json
    target_url = data.get('url')
    consent = data.get('consent')
    
    if not consent:
        return jsonify({"error": "Se requiere autorización explícita para escanear."}), 403
    if not target_url:
        return jsonify({"error": "URL requerida."}), 400
        
    domain = target_url.replace("https://", "").replace("http://", "").split('/')[0]
    
    ports = scan_ports(domain)
    headers = check_security_headers(target_url)
    
    return jsonify({
        "target": domain,
        "open_ports": ports,
        "missing_headers": headers,
        "status": "success"
    })

@app.route('/api/report', methods=['POST'])
def generate_report():
    """FASE 2: El Producto de Pago (Reporte y Mitigación por IA)"""
    data = request.json
    domain = data.get('domain')
    open_ports = data.get('open_ports', [])
    missing_headers = data.get('missing_headers', [])
    payment_status = data.get('payment_status')

    # Validación básica de pago
    if payment_status != 'COMPLETED':
        return jsonify({"error": "Pago requerido para generar el reporte ejecutivo."}), 402

    prompt = f"""
    Actúa como un Auditor de Ciberseguridad B2B. Analiza estos hallazgos para {domain}:
    - Puertos críticos expuestos: {open_ports}
    - Cabeceras de seguridad faltantes: {missing_headers}
    
    Redacta un reporte ejecutivo (3 párrafos) dirigido al CEO de la agencia. 
    Explica el riesgo financiero (inyección SQL, XSS, robo de sesiones) y proporciona las instrucciones técnicas exactas para tu equipo de IT (comandos de iptables o reglas de .htaccess/Nginx) para solucionarlo de inmediato.
    """
    
    headers_api = {
        "Authorization": f"Bearer {AI_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "llama3-8b-8192", 
        "messages": [{"role": "user", "content": prompt}]
    }
    
    try:
        response = requests.post(AI_API_URL, headers=headers_api, json=payload)
        report = response.json()['choices'][0]['message']['content']
        return jsonify({"executive_report": report})
    except Exception as e:
        return jsonify({"error": "Error al conectar con el motor de IA."}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
