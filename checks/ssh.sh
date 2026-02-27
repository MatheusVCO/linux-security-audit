#!/bin/bash

############################################################
# MÓDULO: ACCESS / SSH AUDIT
#
# Objetivo:
# Verificar aderência às políticas de acesso remoto via SSH,
# garantindo que o sistema não esteja exposto a riscos
# relacionados a autenticação fraca ou privilégios excessivos.
#
# Risco Mitigado:
# - Login remoto direto como root
# - Autenticação por senha habilitada
# - Acesso amplo sem restrição explícita
# - Serviço SSH ativo com configuração insegura
#
# Arquitetura:
# - Toda saída passa pela função central de log `log`
# - O módulo retorna código numérico de severidade
# - O main.sh deve consolidar a severidade global
############################################################

set -euo pipefail

############################################################
# SEVERIDADE
#
# 0 = OK
# 1 = INFO
# 2 = WARNING
# 3 = CRITICAL
#
# O módulo mantém a maior severidade encontrada.
############################################################

log() {
    local level="${1:-INFO}" msg="${2:-}"
    local ts
    ts=$(date --rfc-3339=seconds 2>/dev/null || date +"%Y-%m-%d %H:%M:%S")
    printf "%s [%s] %s\n" "$ts" "$level" "$msg"
}

severity=0

set_severity() {
    local v="$1"
    if ! [[ "$v" =~ ^[0-3]$ ]]; then return 0; fi
    if [ "$v" -gt "$severity" ]; then
        severity="$v"
    fi
}

log_level_from() {
    case "$1" in
        0) echo OK;;
        1) echo INFO;;
        2) echo WARNING;;
        3) echo CRITICAL;;
        *) echo INFO;;
    esac
}

############################################################
# COLETA DE CONFIGURAÇÃO
#
# Agrega:
# - /etc/ssh/sshd_config
# - /etc/ssh/sshd_config.d/*.conf
#
# Remove comentários e linhas vazias.
############################################################

gather_sshd_config() {
    local tmp
    tmp=$(mktemp)

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

parse_directive() {
    local key="$1"
    awk -v k="$key" 'BEGIN{IGNORECASE=1} toupper($1)==toupper(k){v=$2} END{if(v)print v}'
}

get_effective_value() {
    local key="$1"; shift
    local explicit="$1"; shift
    case "$key" in
        PermitRootLogin) echo "${explicit:-prohibit-password}";;
        PasswordAuthentication) echo "${explicit:-yes}";;
        *) echo "${explicit:-}";;
    esac
}

main() {

    local cfg
    cfg=$(gather_sshd_config)

    ############################################################
    # CONTROLE 1 — ROOT LOGIN REMOTO
    #
    # Pergunta:
    # O root pode realizar login remoto via SSH?
    #
    # Critério:
    # - CRITICAL se PermitRootLogin=yes
    # - OK se no ou prohibit-password
    # - WARNING se valor inesperado
    ############################################################

    local explicit_prl effective_prl level_prl msg_prl

    explicit_prl=$(printf "%s" "$cfg" | parse_directive PermitRootLogin || true)
    effective_prl=$(get_effective_value PermitRootLogin "$explicit_prl")

    if [ "$effective_prl" = "yes" ]; then
        level_prl=3
        msg_prl="SSH: PermitRootLogin=YES (CRITICAL)"
    elif [ "$effective_prl" = "no" ] || [ "$effective_prl" = "prohibit-password" ]; then
        level_prl=0
        msg_prl="SSH: PermitRootLogin=${effective_prl^^} (seguro)"
    else
        level_prl=2
        msg_prl="SSH: PermitRootLogin=${effective_prl} (valor inesperado)"
    fi

    set_severity "$level_prl"
    log "$(log_level_from "$level_prl")" "$msg_prl"


    ############################################################
    # CONTROLE 2 — AUTENTICAÇÃO POR SENHA
    #
    # Pergunta:
    # PasswordAuthentication está habilitado?
    #
    # Critério:
    # - WARNING se yes
    # - OK se no
    ############################################################

    local explicit_pass effective_pass level_pass msg_pass

    explicit_pass=$(printf "%s" "$cfg" | parse_directive PasswordAuthentication || true)
    effective_pass=$(get_effective_value PasswordAuthentication "$explicit_pass")

    if [ "$effective_pass" = "no" ]; then
        level_pass=0
        msg_pass="SSH: PasswordAuthentication=NO (seguro)"
    else
        level_pass=2
        msg_pass="SSH: PasswordAuthentication=YES (WARNING)"
    fi

    set_severity "$level_pass"
    log "$(log_level_from "$level_pass")" "$msg_pass"


    ############################################################
    # CONTROLE 3 — RESTRIÇÃO DE USUÁRIOS
    #
    # Pergunta:
    # Existe AllowUsers ou AllowGroups?
    #
    # Critério:
    # - INFO se não definido (acesso amplo)
    # - OK se definido
    ############################################################

    local allow_users allow_groups level_allow msg_allow

    allow_users=$(printf "%s" "$cfg" | parse_directive AllowUsers || true)
    allow_groups=$(printf "%s" "$cfg" | parse_directive AllowGroups || true)

    if [ -z "$allow_users" ] && [ -z "$allow_groups" ]; then
        level_allow=1
        msg_allow="SSH: Nenhum AllowUsers/AllowGroups definido (acesso amplo)"
    else
        level_allow=0
        msg_allow="SSH: Acesso restrito configurado"
    fi

    set_severity "$level_allow"
    log "$(log_level_from "$level_allow")" "$msg_allow"


    ############################################################
    # CONTROLE 4 — SERVIÇO SSH ATIVO
    #
    # Verifica se o sshd está ativo no sistema.
    ############################################################

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
        level_srv=1
        msg_srv="SSH: serviço sshd ativo"
    else
        level_srv=0
        msg_srv="SSH: serviço sshd não ativo"
    fi

    set_severity "$level_srv"
    log "$(log_level_from "$level_srv")" "$msg_srv"


    ############################################################
    # RESUMO FINAL DO MÓDULO
    ############################################################

    log "$(log_level_from "$severity")" \
        "SSH: severidade final = $(log_level_from "$severity") (code=$severity)"

    exit "$severity"
}

main "$@"