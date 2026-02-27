#!/bin/bash
# MÓDULO: AUDITORIA SSH
# Toda saída deve passar pela função central de log `log` definida em main.sh (se disponível).

# Segurança e opções
set -euo pipefail

# ---- Logging e severidade local (módulo independente) ----
# Formato de log consistente para integração com main
log() {
    local level="${1:-INFO}" msg="${2:-}"
    local ts
    ts=$(date --rfc-3339=seconds 2>/dev/null || date +"%Y-%m-%d %H:%M:%S")
    printf "%s [%s] %s\n" "$ts" "$level" "$msg"
}


# Severidade: 0=OK,1=INFO,2=WARNING,3=CRITICAL
severity=0
set_severity() {
    local v="$1"
    if ! [[ "$v" =~ ^[0-3]$ ]]; then return 0; fi
    if [ "$v" -gt "$severity" ]; then
        severity="$v"
    fi
}

 # Não há mais modo verbose: sempre loga uma linha por controle

# Helper local para log com nivel derivado da severidade
log_level_from() {
    case "$1" in
        0) echo OK;;
        1) echo INFO;;
        2) echo WARNING;;
        3) echo CRITICAL;;
        *) echo INFO;;
    esac
}

# Severity numeric mapping: 0=OK, 1=INFO, 2=WARNING, 3=CRITICAL
severity_name() {
    case "$1" in
        0) echo OK;;
        1) echo INFO;;
        2) echo WARNING;;
        3) echo CRITICAL;;
        *) echo UNKNOWN;;
    esac
}

# Aggregate config from sshd_config and sshd_config.d
gather_sshd_config() {
    local tmp
    tmp=$(mktemp)
    # Verifica se o arquivo existe e é legível antes de tentar ler
    if [ -f /etc/ssh/sshd_config ]; then
        if [ -r /etc/ssh/sshd_config ]; then
            sed -n 's/#.*$//; /^[[:space:]]*$/d; p' /etc/ssh/sshd_config >> "$tmp" || true
        else
            log "WARNING" "SSH: sem permissão para ler /etc/ssh/sshd_config"
        fi
    fi
    if [ -d /etc/ssh/sshd_config.d ]; then
        for f in /etc/ssh/sshd_config.d/*.conf; do
            [ -e "$f" ] || continue
            if [ -r "$f" ]; then
                sed -n 's/#.*$//; /^[[:space:]]*$/d; p' "$f" >> "$tmp" || true
            else
                log "WARNING" "SSH: sem permissão para ler $f"
            fi
        done
    fi
    cat "$tmp"
    rm -f "$tmp"
}


# Busca valor explícito da diretiva (última ocorrência)
parse_directive() {
    local key="$1"
    awk -v k="$key" 'BEGIN{IGNORECASE=1} toupper($1)==toupper(k){v=$2} END{if(v)print v}'
}

# Determina valor efetivo (explícito ou padrão do sshd)
get_effective_value() {
    local key="$1"; shift
    local explicit="$1"; shift
    # Defaults do OpenSSH 8.x+ (ajustar se necessário)
    case "$key" in
        PermitRootLogin) echo "${explicit:-prohibit-password}";;
        PasswordAuthentication) echo "${explicit:-yes}";;
        *) echo "${explicit:-}";;
    esac
}

main() {
    local cfg
    cfg=$(gather_sshd_config)

    # --- CONTROLE 1: PermitRootLogin ---
    local explicit_prl effective_prl level_prl msg_prl
    explicit_prl=$(printf "%s" "$cfg" | parse_directive PermitRootLogin || true)
    effective_prl=$(get_effective_value PermitRootLogin "$explicit_prl")
    if [ "$effective_prl" = "yes" ]; then
        level_prl=3; msg_prl="SSH: PermitRootLogin=YES ($( [ -n \"$explicit_prl\" ] && echo 'definido manualmente' || echo 'usando padrão do sistema' ), CRITICAL)"
    elif [ "$effective_prl" = "no" ] || [ "$effective_prl" = "prohibit-password" ]; then
        if [ -n "$explicit_prl" ]; then
            level_prl=0; msg_prl="SSH: PermitRootLogin=${effective_prl^^} (definido manualmente, seguro)"
        else
            level_prl=1; msg_prl="SSH: PermitRootLogin=${effective_prl^^} (usando padrão do sistema, seguro)"
        fi
    else
        level_prl=2; msg_prl="SSH: PermitRootLogin=${effective_prl} ($( [ -n \"$explicit_prl\" ] && echo 'definido manualmente' || echo 'usando padrão do sistema' ), valor inesperado)"
    fi
    set_severity "$level_prl"
    log "$(log_level_from "$level_prl")" "$msg_prl"

    # --- CONTROLE 2: PasswordAuthentication ---
    local explicit_pass effective_pass level_pass msg_pass
    explicit_pass=$(printf "%s" "$cfg" | parse_directive PasswordAuthentication || true)
    effective_pass=$(get_effective_value PasswordAuthentication "$explicit_pass")
    if [ "$effective_pass" = "no" ]; then
        if [ -n "$explicit_pass" ]; then
            level_pass=0; msg_pass="SSH: PasswordAuthentication=NO (definido manualmente, seguro)"
        else
            level_pass=1; msg_pass="SSH: PasswordAuthentication=NO (usando padrão do sistema, seguro)"
        fi
    elif [ "$effective_pass" = "yes" ]; then
        level_pass=2; msg_pass="SSH: PasswordAuthentication=YES ($( [ -n \"$explicit_pass\" ] && echo 'definido manualmente' || echo 'usando padrão do sistema' ), WARNING)"
    else
        level_pass=2; msg_pass="SSH: PasswordAuthentication=${effective_pass} ($( [ -n \"$explicit_pass\" ] && echo 'definido manualmente' || echo 'usando padrão do sistema' ), valor inesperado)"
    fi
    set_severity "$level_pass"
    log "$(log_level_from "$level_pass")" "$msg_pass"

    # --- CONTROLE 3: AllowUsers / AllowGroups ---
    local allow_users allow_groups level_allow msg_allow
    allow_users=$(printf "%s" "$cfg" | parse_directive AllowUsers || true)
    allow_groups=$(printf "%s" "$cfg" | parse_directive AllowGroups || true)
    if [ -z "$allow_users" ] && [ -z "$allow_groups" ]; then
        level_allow=1; msg_allow="SSH: Nenhum AllowUsers ou AllowGroups definido (acesso amplo, usando padrão do sistema)"
    else
        level_allow=0; msg_allow="SSH: Acesso restrito via AllowUsers/AllowGroups (explícito)"
    fi
    set_severity "$level_allow"
    log "$(log_level_from "$level_allow")" "$msg_allow"

    # --- CONTROLE 4: Serviço sshd ativo ---
    local active=no level_srv msg_srv
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet sshd 2>/dev/null || systemctl is-active --quiet ssh 2>/dev/null; then
            active=yes
        fi
    else
        if pgrep -x sshd >/dev/null 2>&1; then
            active=yes
        fi
    fi
    if [ "$active" = yes ]; then
        level_srv=1; msg_srv="SSH: serviço sshd ativo"
        if [ "$severity" -eq 0 ]; then set_severity 1; fi
    else
        level_srv=0; msg_srv="SSH: serviço sshd não ativo"
    fi
    log "$(log_level_from "$level_srv")" "$msg_srv"

    # Resumo final
    log "$(log_level_from "$severity")" "SSH: severidade final = $(log_level_from "$severity") (code=$severity)"

    exit "$severity"
}

main "$@"
