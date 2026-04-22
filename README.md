# Docker Security Scanner

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Security Tool](https://img.shields.io/badge/Segurança-Ferramenta-red?logo=shield&logoColor=white)
![Licença](https://img.shields.io/badge/Licença-MIT-green?logoColor=white)
![Testes](https://img.shields.io/badge/Testes-105%20passando-brightgreen)

Uma ferramenta CLI leve que analisa estaticamente arquivos `docker-compose.yml` e `Dockerfile` em busca de más práticas de segurança, gerando relatórios coloridos no terminal ou saída JSON para integração com pipelines.

O Docker Security Scanner implementa 20 regras (10 por tipo de arquivo) cobrindo os erros de segurança mais impactantes em containers: rodar como root, colocar segredos dentro da imagem, expor portas privilegiadas, montar o socket do Docker, usar imagens base sem suporte, entre outros. Não precisa de Docker rodando, não acessa a internet e não usa frameworks pesados — só Python e duas dependências pequenas.

---

## Instalação

```bash
git clone https://github.com/NathaliaGF/docker-security-scanner.git
cd docker-security-scanner
pip install -r requirements.txt
```

Requer Python 3.10 ou superior.

---

## Como usar

### Analisar um arquivo específico

```bash
python main.py --file docker-compose.yml
python main.py --file caminho/para/Dockerfile
```

### Analisar um diretório inteiro (recursivo)

```bash
python main.py --dir ./meu-projeto
```

### Filtrar por severidade

```bash
# Exibir apenas achados críticos
python main.py --file docker-compose.yml --severity HIGH
```

### Exportar como JSON (para pipelines, dashboards, etc.)

```bash
python main.py --file docker-compose.yml --output json
python main.py --dir ./meu-projeto --output json > relatorio.json
```

### Integração com CI/CD

O scanner encerra com código `1` quando há qualquer achado **HIGH**, e `0` caso contrário. Isso permite bloquear pipelines em problemas críticos:

```yaml
# Exemplo GitHub Actions
- name: Docker Security Scan
  run: python main.py --dir . --severity HIGH
```

---

## Checks implementados

### docker-compose.yml

| ID     | Severidade | Descrição                                                        |
|--------|------------|------------------------------------------------------------------|
| DC001  | HIGH       | Container rodando como root (sem `user:` ou `user: root`)        |
| DC002  | HIGH       | Porta privilegiada exposta no host (< 1024)                      |
| DC003  | MEDIUM     | Imagem usando tag `latest` ou sem tag                            |
| DC004  | HIGH       | Volume sensível montado (`/`, `/etc`, socket do Docker)          |
| DC005  | MEDIUM     | Segredo em texto plano em variável de ambiente                   |
| DC006  | LOW        | `restart: always` sem health check definido                      |
| DC007  | HIGH       | `privileged: true` habilitado                                    |
| DC008  | MEDIUM     | Modo de rede host (`network_mode: host`)                         |
| DC009  | LOW        | Sem limites de CPU ou memória definidos                          |
| DC010  | MEDIUM     | Capabilities Linux perigosas adicionadas (`SYS_ADMIN`, `ALL`…)  |

### Dockerfile

| ID     | Severidade | Descrição                                                        |
|--------|------------|------------------------------------------------------------------|
| DF001  | HIGH       | `USER root` explícito ou ausência de instrução `USER`            |
| DF002  | MEDIUM     | Imagem base usando tag `latest` ou sem tag                       |
| DF003  | HIGH       | Credenciais hardcoded em `ENV` ou `ARG`                          |
| DF004  | MEDIUM     | `apt-get install` sem `--no-install-recommends`                  |
| DF005  | LOW        | `COPY . .` sem arquivo `.dockerignore`                           |
| DF006  | MEDIUM     | Script remoto executado via pipe (`curl \| bash`)                 |
| DF007  | LOW        | Mais de 3 instruções `RUN` consecutivas                          |
| DF008  | MEDIUM     | Porta sensível exposta via `EXPOSE` (22, 23, 3389)               |
| DF009  | HIGH       | Chave privada ou certificado TLS copiado para dentro da imagem   |
| DF010  | LOW        | Imagem base sem suporte (`ubuntu:16.04`, `debian:8`…)            |

---

## Score de segurança

Cada análise gera uma pontuação de **0 a 100**:

| Severidade | Dedução por achado |
|------------|--------------------|
| HIGH       | −15 pontos         |
| MEDIUM     | −7 pontos          |
| LOW        | −2 pontos          |

O score é calculado sobre a lista completa de achados, independente do filtro `--severity` aplicado na exibição.

---

## Exemplo de saída

```
╔══════════════════════════════════════════════════════════╗
║           DOCKER SECURITY SCANNER — RELATÓRIO            ║
╚══════════════════════════════════════════════════════════╝

📄 Arquivo: tests/samples/docker-compose.insecure.yml
──────────────────────────────────────────────────────────

🔴 [HIGH  ] DC007 — `privileged: true` habilitado
            Serviço: api
            Linha:   19
            Detalhe: Um container privilegiado tem acesso total ao kernel do host,
                     todos os dispositivos e namespaces — equivalente a root no host.
            Fix:     Remova `privileged: true` e use `cap_add` apenas com as
                     capabilities estritamente necessárias.

🟡 [MEDIUM] DC003 — Imagem com tag `latest` (ou sem tag)
            Serviço: db
            Linha:   26
            Detalhe: Usar `latest` torna as builds não reproduzíveis: atualizações
                     upstream podem introduzir breaking changes sem aviso.
            Fix:     Fixe uma versão específica, ex: `postgres:16.2`.

🔵 [LOW   ] DC009 — Sem limites de CPU ou memória
            Serviço: api
            Linha:   8
            Detalhe: Sem `mem_limit`/`cpus`, um container com problema pode
                     esgotar todos os recursos do host (DoS).
            Fix:     Defina `mem_limit` e `cpus` no serviço.

──────────────────────────────────────────────────────────
RESUMO: 14 achados  |  🔴 HIGH: 5  |  🟡 MEDIUM: 6  |  🔵 LOW: 3
Score de segurança: 0/100
──────────────────────────────────────────────────────────
```

### Saída JSON (`--output json`)

```json
{
  "file": "docker-compose.yml",
  "score": 62,
  "total_findings": 3,
  "findings": [
    {
      "id": "DC007",
      "severity": "HIGH",
      "description": "`privileged: true` habilitado",
      "detail": "Um container privilegiado tem acesso total ao kernel do host...",
      "fix": "Remova `privileged: true` e use `cap_add` apenas com as capabilities necessárias.",
      "service": "api",
      "line": 12
    }
  ],
  "summary": {
    "HIGH": 1,
    "MEDIUM": 1,
    "LOW": 1
  }
}
```

---

## Rodando os testes

```bash
pytest tests/ -v
```

A suíte contém **105 testes** — pelo menos um caso positivo e um negativo por check, mais testes de integração contra os arquivos de exemplo em `tests/samples/`.

---

## Roadmap

- **Scan de imagens remotas** — buscar metadados via Docker API e analisar o histórico de camadas em busca de segredos e imagens base vulneráveis.
- **Integrações CI/CD** — action nativa para GitHub Actions e template para GitLab CI; saída no formato SARIF para o GitHub Code Scanning.
- **Suporte a manifests Kubernetes** — estender os checks para `Pod`, `Deployment` e `DaemonSet` (regras equivalentes para `securityContext`, `hostNetwork`, `privileged`, etc.).
- **Motor de regras customizadas** — permitir que times definam regras específicas do projeto em YAML e as carreguem em tempo de execução.
- **Integração com SBOM** — cruzar as camadas da imagem base com bancos de CVEs (Trivy, Grype) para incluir contagem de vulnerabilidades junto aos achados de configuração.

---

## Licença

MIT — consulte o arquivo [LICENSE](LICENSE) para detalhes.
