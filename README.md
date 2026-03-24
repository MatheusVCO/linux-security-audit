# linux-security-audit

Automação de auditorias básicas de segurança em Linux com foco em hardening, visibilidade operacional e identificação rápida de desvios relevantes.

This project automates basic Linux security checks focused on hardening and fast operational visibility.

## Visão geral

O projeto executa uma auditoria local em quatro frentes:

- rede
- serviços
- SSH
- usuários e privilégios

Ao final da execução, o script consolida os achados em:

- um log principal em `report/`
- um relatório-resumo em texto em `report/`
- um baseline de sockets de rede para comparação entre execuções

O objetivo aqui não é substituir scanners completos ou ferramentas de compliance formal. A proposta é entregar um ponto de partida simples, legível e fácil de adaptar.

## O que o projeto verifica

### Network

- portas e sockets em escuta
- serviços escutando em todas as interfaces
- presença de firewall ativo ou regras configuradas
- política básica de firewall
- interfaces de rede ativas
- exposição de serviços sensíveis como SSH, MySQL, PostgreSQL, Redis e MongoDB
- comparação com baseline anterior de sockets em escuta

### Services

- serviços ativos no sistema
- serviços habilitados no boot
- presença de serviços sensíveis ou críticos
- serviços em estado `failed`
- serviços perigosos que idealmente deveriam estar `masked`

### SSH

- `PermitRootLogin`
- `PasswordAuthentication`
- existência de `AllowUsers` ou `AllowGroups`
- presença do serviço `sshd` em execução

### Users

- identificação de usuários humanos
- detecção de contas administrativas
- comparação opcional com baseline de administradores autorizados
- múltiplas contas com UID 0
- contas de sistema com shell interativa
- leitura de `/etc/shadow` quando disponível para detectar senha vazia

## Estrutura do projeto

```text
.
├── main.sh
├── checks/
│   ├── network.sh
│   ├── services.sh
│   ├── ssh.sh
│   └── users.sh
├── lib/
│   └── common.sh
└── report/
```

## Requisitos

Requisitos mínimos:

- Bash
- ambiente Linux
- `ss`
- `ip`
- `systemctl` para a maior parte das verificações de serviços
- `getent`

Ferramentas detectadas opcionalmente:

- `ufw`
- `firewall-cmd`
- `nft`
- `iptables` e `iptables-save`
- `pgrep`

Algumas verificações ficam mais completas quando executadas com privilégios elevados, especialmente as relacionadas a `/etc/shadow`, serviços do sistema e configuração de firewall.

## Como executar

Execução completa:

```bash
bash main.sh
```

Se o arquivo estiver executável:

```bash
./main.sh
```

Execução de módulos individualmente:

```bash
bash checks/network.sh
bash checks/services.sh
bash checks/ssh.sh
bash checks/users.sh
```

Ajuda do módulo de usuários:

```bash
bash checks/users.sh -h
```

## Saída gerada

Cada execução do orquestrador principal gera arquivos em `report/` com timestamp.

Exemplos:

```text
report/audit_20260323_212730.log
report/audit_20260323_212730_summary.txt
report/network_ss_baseline.txt
```

O relatório consolidado inclui:

- severidade global
- severidade por módulo
- logs completos por seção
- interpretação dos níveis de severidade

## Códigos de saída

No `main.sh`, o código de saída representa a severidade global encontrada:

- `0`: OK
- `1`: INFO
- `2`: WARNING
- `3`: CRITICAL

Nos módulos individuais, o código pode variar conforme a implementação interna de cada script, mas em geral segue a ideia de retornar sucesso para achados informativos e códigos não zero para alertas mais relevantes.

## Exemplos de uso

Auditoria completa local:

```bash
./main.sh
```

Auditoria apenas de usuários com baseline explícito:

```bash
bash checks/users.sh -b admins.baseline -m 3
```

Gerar um baseline inicial de administradores autorizados:

```bash
bash checks/users.sh -w admins.baseline
```

## Limitações atuais

- foco em verificações locais e heurísticas simples
- não substitui benchmark CIS, Lynis, OpenSCAP ou auditorias formais
- parte da lógica assume utilitários comuns em distribuições com `systemd`
- alguns comentários internos citam opções ainda não expostas pelo `main.sh`
- os módulos não compartilham exatamente o mesmo formato interno de log

## Quando usar

Este projeto é útil para:

- revisar rapidamente a superfície de ataque de uma máquina Linux
- validar configurações básicas após provisionamento
- comparar exposição de portas entre execuções
- identificar contas administrativas inesperadas
- criar uma base inicial de auditoria em Bash para customização interna

## Convenção de commits

Use mensagens curtas, específicas e orientadas ao escopo da mudança.

Formato recomendado:

```text
tipo(escopo): descrição
```

Exemplos:

```text
fix(network): corrigir detecção de regras iptables
refactor(services): remover checagens redundantes de systemctl
docs(readme): adicionar convenção de commits
chore(report): remover script obsoleto
```

Tipos sugeridos:

- `fix`: correção de bug
- `feat`: nova funcionalidade
- `refactor`: refatoração sem mudança funcional esperada
- `docs`: documentação
- `chore`: manutenção geral

Recommended format:

```text
type(scope): description
```
