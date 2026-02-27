#!/bin/bash

############################################################
# MÓDULO: IDENTITY / USERS AUDIT
#
# Objetivo:
# Verificar aderência à política de menor privilégio
# relacionada à identidade e privilégios de usuários.
#
# Risco Mitigado:
# - Escalada de privilégio indevida
# - Contas administrativas não autorizadas
# - Contas humanas fora do baseline definido
# - Contas de sistema com acesso interativo indevido
#
# Arquitetura:
# - Coleta informações via getent (compatível com LDAP/SSSD)
# - Classifica usuários humanos e administrativos
# - Valida contra baseline opcional
# - Registra anomalias estruturadas em log
# - Retorna exit code baseado na maior severidade encontrada
############################################################

set -euo pipefail

############################################################
# PARÂMETROS E CONFIGURAÇÃO
#
# HUMAN_UID_MIN:
#   UID mínimo considerado humano.
#
# HUMAN_UID_MAX:
#   UID máximo opcional (evita limite arbitrário por padrão).
#
# ADMIN_MAX:
#   Número máximo aceitável de contas administrativas.
#
# BASELINE_FILE:
#   Arquivo contendo usuários administrativos autorizados.
#
# WRITE_BASELINE:
#   Permite gerar baseline inicial a partir do estado atual.
############################################################

# Defaults
HUMAN_UID_MIN=${HUMAN_UID_MIN:-1000}
HUMAN_UID_MAX=${HUMAN_UID_MAX:-}
ADMIN_MAX=${ADMIN_MAX:-3}
BASELINE_FILE=""
WRITE_BASELINE=""

usage(){
	cat <<EOF
Uso: $0 [-b arquivo_baseline] [-m max_admins] [-u min_human_uid] [-x max_human_uid] [-w write_baseline]

Opções:
	-b arquivo_baseline   Arquivo com um usuário administrador autorizado por linha
	-m max_admins         Limite para número de administradores (padrão: $ADMIN_MAX)
	-u min_human_uid      UID mínimo considerado humano (padrão: $HUMAN_UID_MIN)
	-x max_human_uid      UID máximo considerado humano (padrão: sem limite superior)
	-w write_baseline     Grava a lista atual de administradores no arquivo informado (sobrescreve)
	-h                    Mostra esta ajuda
EOF
	exit 1
}

while getopts ":b:m:u:x:w:h" opt; do
	case $opt in
		b) BASELINE_FILE="$OPTARG" ;;
		m) ADMIN_MAX="$OPTARG" ;;
		u) HUMAN_UID_MIN="$OPTARG" ;;
		x) HUMAN_UID_MAX="$OPTARG" ;;
  	w) WRITE_BASELINE="$OPTARG" ;;
		h) usage ;;
		*) usage ;;
	esac
done

############################################################
# DEFINIÇÃO DE SHELLS INTERATIVOS
#
# SHELL_WHITELIST:
#   Define shells considerados interativos (indicativo de
#   conta humana).
#
# NOLOGIN_PATTERNS:
#   Padrões típicos de shells não interativas.
############################################################

SHELL_WHITELIST=(/bin/bash /bin/sh /bin/zsh /bin/ksh /usr/bin/bash /usr/bin/zsh)
NOLOGIN_PATTERNS=(/sbin/nologin /usr/sbin/nologin /bin/false /usr/bin/false)

############################################################
# OBSERVAÇÃO IMPORTANTE SOBRE SUDOERS
#
# Este módulo detecta privilégios administrativos amplos
# (ALL=(ALL) ou permissões equivalentes).
#
# NÃO interpreta completamente a gramática sudoers:
# - Aliases complexos
# - Cmnd_Alias específicos
# - Restrições de host
# - RunAs complexos
#
# Foco: detectar contas com capacidade administrativa ampla.
############################################################

in_array(){
	local v pat
	v="$1"; shift
	for pat in "$@"; do
		[[ "$v" == "$pat" ]] && return 0
	done
	return 1
}

# Coleta entradas de passwd (compatível com LDAP/SSSD via getent)
mapfile -t PASSWD_LINES < <(getent passwd)

# ############################################################
# CONTROLE 1 — IDENTIFICAÇÃO DE USUÁRIOS HUMANOS
#
# Pergunta:
# Quais contas representam usuários humanos ativos?
#
# Critério:
# - UID >= HUMAN_UID_MIN
# - (Opcionalmente <= HUMAN_UID_MAX)
# - Shell interativa válida
# - Diretório home existente
#
# Objetivo:
# Separar identidade humana de contas de serviço.
# ############################################################
human_users=()
is_interactive_shell(){
	local s="$1"
	in_array "$s" "${SHELL_WHITELIST[@]}"
}

for line in "${PASSWD_LINES[@]}"; do
	IFS=: read -r username passwd uid gid gecos home shell <<<"$line"
	# ensure numeric comparison safe
	if (( uid >= HUMAN_UID_MIN )); then
		if [ -z "$HUMAN_UID_MAX" ] || (( uid <= HUMAN_UID_MAX )); then
			if is_interactive_shell "$shell"; then
				if [ -n "$home" ] && [ -d "$home" ]; then
					human_users+=("$username")
				fi
			fi
		fi
	fi
done

# ############################################################
# CONTROLE 2 — IDENTIFICAÇÃO DE USUÁRIOS ADMINISTRATIVOS
#
# Pergunta:
# Quais contas possuem privilégio administrativo?
#
# Critério:
# - Membros de grupos sudo ou wheel
# - Entradas explícitas amplas em sudoers
#
# Objetivo:
# Identificar contas com capacidade de elevação de privilégio.
# ############################################################
declare -A admin_set=()

# Membros de grupos administrativos comuns
for g in sudo wheel; do
	if getent group "$g" >/dev/null 2>&1; then
		members=$(getent group "$g" | awk -F: '{print $4}')
		IFS=, read -r -a arr <<<"$members"
		for u in "${arr[@]}"; do
			[ -z "$u" ] && continue
			admin_set["$u"]=1
		done
	fi
done

# Analisa /etc/sudoers e /etc/sudoers.d para entradas de usuário ou %grupo
sudoers_files=(/etc/sudoers)
if [ -d /etc/sudoers.d ]; then
	while IFS= read -r -d $'\0' f; do sudoers_files+=("$f"); done < <(find /etc/sudoers.d -type f -print0 2>/dev/null || true)
fi

for f in "${sudoers_files[@]}"; do
	[ -r "$f" ] || continue
	# grupos referenciados como %group
	while read -r gline; do
		grp=$(sed -E 's/.*%([A-Za-z0-9_\-]+).*/\1/' <<<"$gline")
		if [ -n "$grp" ]; then
			members=$(getent group "$grp" | awk -F: '{print $4}')
			IFS=, read -r -a arr <<<"$members"
			for u in "${arr[@]}"; do [ -n "$u" ] && admin_set["$u"]=1; done
		fi
	done < <(grep -E '(^|[^#])%[A-Za-z0-9_\-]+' "$f" 2>/dev/null || true)

	# linhas de usuário explícitas, ex.: someuser ALL=(ALL) NOPASSWD: ALL
	while read -r uline; do
		user=$(sed -E 's/^([^#[:space:]]+).*/\1/' <<<"$uline")
		if [ -n "$user" ]; then admin_set["$user"]=1; fi
	done < <(grep -E '^[[:alnum:]._-]+[[:space:]]+ALL\s*=\(' "$f" 2>/dev/null || true)
done

# Converte admin_set em array
admin_users=()
for u in "${!admin_set[@]}"; do
	admin_users+=("$u")
done

# Opcional: grava a lista atual de administradores em um arquivo baseline (útil para bootstrap)
if [ -n "$WRITE_BASELINE" ]; then
	printf '%s
' "${admin_users[@]}" > "$WRITE_BASELINE"
fi

# ############################################################
# CONTROLE 3 — VALIDAÇÃO CONTRA BASELINE
#
# Pergunta:
# Os administradores atuais estão aderentes ao baseline?
#
# Critério:
# - Detectar administradores não autorizados
# - Detectar administradores esperados ausentes
#
# Objetivo:
# Garantir controle formal sobre privilégio administrativo.
# ############################################################
authorized_admins=()
unauthorized_admins=()
missing_admins=()
if [ -n "$BASELINE_FILE" ] && [ -r "$BASELINE_FILE" ]; then
	mapfile -t authorized_admins < <(sed -E 's/#.*//' "$BASELINE_FILE" | sed '/^\s*$/d')
	declare -A base_set=()
	for u in "${authorized_admins[@]}"; do base_set["$u"]=1; done
	for u in "${admin_users[@]}"; do
		if [ -z "${base_set[$u]:-}" ]; then
			unauthorized_admins+=("$u")
		fi
	done
	for u in "${authorized_admins[@]}"; do
		if ! printf '%s\n' "${admin_users[@]}" | grep -xq -- "$u"; then
			missing_admins+=("$u")
		fi
	done
fi

# ############################################################
# CONTROLE 4 — DETECÇÃO DE ANOMALIAS
#
# Subcontroles:
#
# 1) Múltiplas contas com UID 0
#    - CRITICAL se existir mais de uma conta UID 0
#
# 2) Número excessivo de administradores
#    - WARNING se ultrapassar ADMIN_MAX
#
# 3) Conta de sistema com shell interativa
#    - WARNING se UID < HUMAN_UID_MIN e shell interativa
#
# 4) Conta com senha vazia em /etc/shadow
#    - CRITICAL se detectado
#
# Objetivo:
# Detectar desvios graves de política de identidade.
# ############################################################
anomalies=()
highest_severity=0

add_anomaly(){
	local sev="$1"; shift; local msg="$*"
	anomalies+=("$sev: $msg")
	if [ "$sev" = "CRITICAL" ]; then highest_severity=2; fi
	if [ "$sev" = "WARNING" ] && [ "$highest_severity" -lt 1 ]; then highest_severity=1; fi
}

# 1) UID 0 além do root
uids0=()
for line in "${PASSWD_LINES[@]}"; do
	IFS=: read -r username passwd uid gid gecos home shell <<<"$line"
	if [ "$uid" = "0" ]; then uids0+=("$username"); fi
done
if [ "${#uids0[@]}" -gt 1 ]; then
	add_anomaly "CRITICAL" "Múltiplas contas com UID 0: ${uids0[*]}"
fi

# 2) Excesso de contas administrativas
if [ "${#admin_users[@]}" -gt "$ADMIN_MAX" ]; then
	add_anomaly "WARNING" "${#admin_users[@]} contas administrativas (limite $ADMIN_MAX)"
fi

# 3) System accounts with interactive shell
for line in "${PASSWD_LINES[@]}"; do
	IFS=: read -r username passwd uid gid gecos home shell <<<"$line"
	if is_interactive_shell "$shell"; then
		# Considera anomalia de conta de sistema com shell interativa somente quando UID está abaixo
		# do limite humano e não for root (root normalmente tem UID 0 e pode ter shell interativa)
		if (( uid < HUMAN_UID_MIN )) && [ "$username" != "root" ]; then
			add_anomaly "WARNING" "Conta de sistema com shell interativa: $username (UID $uid, shell $shell)"
		fi
	fi
done

# 4) Contas sem senha (requer /etc/shadow)
if [ -r /etc/shadow ]; then
	while IFS=: read -r user pass rest; do
		if [ -z "$pass" ]; then
			add_anomaly "CRITICAL" "Conta com campo de senha vazio em /etc/shadow: $user"
		fi
	done < /etc/shadow
else
	if [ "$(id -u)" -ne 0 ]; then
		add_anomaly "INFO" "Executando sem privilégios; pulando checagem de /etc/shadow"
	else
		add_anomaly "WARNING" "Não é possível ler /etc/shadow; pulando checagem de senhas"
	fi
fi

 
log_line(){
	local sev="$1"; shift; local msg="$*"
	printf '%s [%s] %s\n' "$(date --rfc-3339=seconds 2>/dev/null || date +"%Y-%m-%d %H:%M:%S")" "$sev" "$msg"
}

# ############################################################
# LOG E SAÍDA
#
# O módulo:
# - Registra resumo de usuários humanos
# - Registra administradores
# - Lista anomalias individualmente
# - Retorna exit code:
#     0 = apenas INFO
#     1 = WARNING presente
#     2 = CRITICAL presente
#
# Esse exit code deve ser consolidado pelo main.sh.
# ############################################################
	log_line "INFO" "Usuários humanos: ${#human_users[@]}"
if [ ${#human_users[@]} -gt 0 ]; then
	human_csv=$(IFS=, ; echo "${human_users[*]}")
		log_line "INFO" "Lista de usuários humanos: ${human_csv}"
fi
	log_line "INFO" "Administradores: ${#admin_users[@]}"
if [ ${#admin_users[@]} -gt 0 ]; then
	admin_csv=$(IFS=, ; echo "${admin_users[*]}")
		log_line "INFO" "Lista de administradores: ${admin_csv}"
fi
if [ -n "$BASELINE_FILE" ]; then
		log_line "INFO" "Administradores não autorizados: ${#unauthorized_admins[@]}"
		log_line "INFO" "Administradores esperados ausentes: ${#missing_admins[@]}"
fi
	log_line "INFO" "Anomalias: ${#anomalies[@]}"
for a in "${anomalies[@]}"; do
	sev=${a%%:*}
	msg=${a#*: }
	log_line "$sev" "$msg"
done

# Exit code based on highest severity: 0 INFO-only, 1 WARNING present, 2 CRITICAL present
exit_code=0
if [ "$highest_severity" -ge 2 ]; then exit_code=2
elif [ "$highest_severity" -ge 1 ]; then exit_code=1
fi

exit $exit_code