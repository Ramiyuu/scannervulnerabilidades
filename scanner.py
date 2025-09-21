import os
import re
import requests
import csv
import io

# --- Funções de CVE / Exploit-DB ---
def buscar_cves_nvd(lib, versao):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={lib}%20{versao}"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code != 200:
            return []
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        cves = []
        for v in vulns[:5]:
            cve = v["cve"]["id"]
            desc = v["cve"]["descriptions"][0]["value"]
            cves.append((cve, desc[:200]))
        return cves
    except:
        return []

def buscar_exploits(cve_id):
    url = "https://raw.githubusercontent.com/offensive-security/exploitdb/main/files_exploits.csv"
    try:
        resp = requests.get(url, timeout=20)
        if resp.status_code != 200:
            return []
        exploits = []
        csv_data = resp.content.decode("utf-8", errors="ignore")
        reader = csv.reader(io.StringIO(csv_data))
        for row in reader:
            if cve_id in row[-1]:
                exploits.append({
                    "id": row[0],
                    "title": row[2],
                    "url": f"https://www.exploit-db.com/exploits/{row[0]}"
                })
        return exploits
    except:
        return []

# --- Função para analisar cada arquivo ---
def analisar_arquivo(caminho, relatorio_html):
    print(f"\n=== Analisando {caminho} ===")
    with open(caminho, "r", encoding="utf-8", errors="ignore") as f:
        conteudo = f.read()

    relatorio_html.append(f"<h2>Arquivo: {caminho}</h2>")

    # Padrões inseguros
    padroes = {
        r"\beval\(": "Uso de eval (pode causar RCE)",
        r"\bexec\(": "Uso de exec (pode causar RCE)",
        r"SELECT\s+.*\s+\+": "Possível SQL Injection (query concatenada)",
        r"password\s*=\s*[\"'].*[\"']": "Senha hardcoded",
        r"debug\s*=\s*True": "Debug ativo (Security Misconfiguration)"
    }
    relatorio_html.append("<ul>")
    achou_padrao = False
    for regex, alerta in padroes.items():
        if re.search(regex, conteudo, re.IGNORECASE):
            print(f"⚠️ {alerta}")
            relatorio_html.append(f"<li class='alerta'>⚠️ {alerta}</li>")
            achou_padrao = True
    if not achou_padrao:
        relatorio_html.append("<li class='ok'>✅ Nenhum padrão inseguro detectado</li>")
    relatorio_html.append("</ul>")

    # OWASP Top 10
    owasp_regras = {
        "A01: Broken Access Control": [r"if\s+user\.isAdmin"],
        "A02: Cryptographic Failures": [r"\bmd5\(", r"\bsha1\(", r"http://"],
        "A03: Injection": [r"\beval\(", r"\bexec\(", r"SELECT\s+.*\s+\+"],
        "A05: Security Misconfiguration": [r"debug\s*=\s*True"],
        "A07: Identification and Authentication Failures": [r"password\s*=\s*[\"'].*[\"']"],
        "A08: Software and Data Integrity Failures": [r"wget ", r"curl "],
        "A10: Server-Side Request Forgery (SSRF)": [r"requests\.get\(", r"urllib\.request"]
    }
    relatorio_html.append("<ul>")
    achou_owasp = False
    for categoria, regras in owasp_regras.items():
        for regex in regras:
            if re.search(regex, conteudo, re.IGNORECASE):
                print(f"⚠️ {categoria} detectado → padrão: {regex}")
                relatorio_html.append(f"<li class='alerta'>⚠️ {categoria} detectado → padrão: {regex}</li>")
                achou_owasp = True
    if not achou_owasp:
        relatorio_html.append("<li class='ok'>✅ Nenhum padrão OWASP detectado</li>")
    relatorio_html.append("</ul>")

    # Dependências e CVEs
    libs = re.findall(r"([a-zA-Z0-9_\-]+)[=:-]+(\d+\.\d+(\.\d+)*)", conteudo)
    relatorio_html.append("<h3>Dependências</h3><ul>")
    if not libs:
        relatorio_html.append("<li class='ok'>Nenhuma dependência/versão detectada.</li>")
    else:
        for lib, versao, _ in libs:
            relatorio_html.append(f"<li><b>{lib} {versao}</b><ul>")
            cves = buscar_cves_nvd(lib, versao)
            if not cves:
                relatorio_html.append("<li class='ok'>✅ Nenhuma vulnerabilidade na NVD</li>")
            else:
                for cve_id, desc in cves:
                    relatorio_html.append(f"<li class='alerta'>{cve_id}: {desc}</li>")
                    exploits = buscar_exploits(cve_id)
                    if exploits:
                        relatorio_html.append("<ul>")
                        for exp in exploits:
                            relatorio_html.append(f"<li class='exploit'>{exp['title']} - <a href='{exp['url']}' target='_blank'>{exp['url']}</a></li>")
                        relatorio_html.append("</ul>")
                    else:
                        relatorio_html.append("<li class='ok'>✅ Nenhum exploit público</li>")
            relatorio_html.append("</ul></li>")
    relatorio_html.append("</ul>")

# --- Função principal: varrer a pasta atual ---
def analisar_pasta_atual():
    relatorio_html = ["<html><head><meta charset='UTF-8'><title>Relatório de Segurança</title>"]
    relatorio_html.append("<style>body{font-family:Arial;padding:20px;background:#f9f9f9;} h2{color:#333;} .alerta{color:red;} .ok{color:green;} .exploit{color:darkred;}</style></head><body>")
    relatorio_html.append("<h1>🔎 Relatório de Segurança da Pasta Atual</h1>")

    extensoes = [".php", ".html", ".js", ".py"]
    for root, dirs, files in os.walk("."):
        for file in files:
            if any(file.lower().endswith(ext) for ext in extensoes):
                caminho = os.path.join(root, file)
                analisar_arquivo(caminho, relatorio_html)

    relatorio_html.append("</body></html>")
    with open("relatorio.html", "w", encoding="utf-8") as f:
        f.write("\n".join(relatorio_html))
    print("\n📄 Relatório gerado: relatorio.html")

# --- Execução ---
if __name__ == "__main__":
    analisar_pasta_atual()
