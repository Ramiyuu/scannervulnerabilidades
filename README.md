# Scanner de Vulnerabilidades - OWASP Top 10, CVE e Exploit-DB

Este projeto é um **scanner de código e dependências** que identifica possíveis vulnerabilidades em arquivos de projetos. Ele analisa tanto **padrões inseguros e OWASP Top 10**, quanto **dependências com CVEs conhecidos** e **exploits públicos** no Exploit-DB.

---

## 🔹 Funcionalidades

- Análise de arquivos **`.php`, `.html`, `.js`, `.py`** na pasta atual e subpastas.
- Detecção de padrões inseguros como:
  - Uso de `eval` ou `exec` (RCE)
  - SQL Injection (queries concatenadas)
  - Senhas hardcoded
  - Debug ativo em frameworks (ex.: Flask, Django)
- Verificação de **OWASP Top 10** (heurísticas simples)
- Identificação de **dependências vulneráveis**
- Consulta a **CVE** na NVD
- Consulta a **exploits públicos** no Exploit-DB
- Geração de **relatório HTML completo** com todos os achados

---

## 🔹 Requisitos

- Python 3.8 ou superior
- Biblioteca `requests`

Instale a biblioteca com:

```bash
pip install -r requirements.txt
