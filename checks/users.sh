#!/bin/bash

############################################################
# MÓDULO: USERS AUDIT
#
# Objetivo:
# Verificar aderência à política de menor privilégio
# relacionada a usuários do sistema.
#
# Risco Mitigado:
# - Escalada de privilégio indevida
# - Contas administrativas não autorizadas
# - Contas humanas não previstas
# - Contas de serviço com acesso interativo indevido
############################################################

set -euo pipefail

# Defaults
HUMAN_UID_MIN=${HUMAN_UID_MIN:-1000}
# Leave HUMAN_UID_MAX empty by default to avoid arbitrary upper bound
HUMAN_UID_MAX=${HUMAN_UID_MAX:-}
ADMIN_MAX=${ADMIN_MAX:-3}
BASELINE_FILE=""
WRITE_BASELINE=""

usage(){
	cat <<EOF
Usage: $0 [-b baseline_file] [-m max_admins] [-u min_human_uid] [-x max_human_uid] [-w write_baseline]

Options:
	-b baseline_file   File with one authorized admin username per line
	-m max_admins      Threshold for number of admins (default: $ADMIN_MAX)
	-u min_human_uid   Minimum UID considered human (default: $HUMAN_UID_MIN)
	-x max_human_uid   Maximum UID considered human (default: no upper bound)
	-w write_baseline   Write current admin list to given file (overwrites)
	-h                 Show this help
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

SHELL_WHITELIST=(/bin/bash /bin/sh /bin/zsh /bin/ksh /usr/bin/bash /usr/bin/zsh)
NOLOGIN_PATTERNS=(/sbin/nologin /usr/sbin/nologin /bin/false /usr/bin/false)

# Note: parsing sudoers/sudoers.d here aims to detect broad administrative access
# (users/groups allowed to run ALL). This does NOT parse the full sudoers grammar
# (Aliases, Cmnd_Alias, Host_Alias, complex RunAs restrictions, or command-limited
# entries). The module reports users with wide sudo capabilities; restricted sudo
# grants (single commands) may not be detected.

in_array(){
	local v pat
	v="$1"; shift
	for pat in "$@"; do
		[[ "$v" == "$pat" ]] && return 0
	done
	return 1
}

# Gather passwd entries
mapfile -t PASSWD_LINES < <(getent passwd)

# CONTROL 1 — IDENTIFICAÇÃO DE USUÁRIOS HUMANOS
human_users=()
# prefer interactive-shell as main signal for human accounts; UID lower bound still applied
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

# CONTROL 2 — IDENTIFICAÇÃO DE USUÁRIOS ADMINISTRATIVOS
declare -A admin_set=()

# Members of common admin groups
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

# Parse /etc/sudoers and /etc/sudoers.d for explicit user or %group entries
sudoers_files=(/etc/sudoers)
if [ -d /etc/sudoers.d ]; then
	while IFS= read -r -d $'\0' f; do sudoers_files+=("$f"); done < <(find /etc/sudoers.d -type f -print0 2>/dev/null || true)
fi

for f in "${sudoers_files[@]}"; do
	[ -r "$f" ] || continue
	# groups referenced as %group
	while read -r gline; do
		grp=$(sed -E 's/.*%([A-Za-z0-9_\-]+).*/\1/' <<<"$gline")
		if [ -n "$grp" ]; then
			members=$(getent group "$grp" | awk -F: '{print $4}')
			IFS=, read -r -a arr <<<"$members"
			for u in "${arr[@]}"; do [ -n "$u" ] && admin_set["$u"]=1; done
		fi
	done < <(grep -E '(^|[^#])%[A-Za-z0-9_\-]+' "$f" 2>/dev/null || true)

	# explicit user lines like: someuser ALL=(ALL) NOPASSWD: ALL
	while read -r uline; do
		user=$(sed -E 's/^([^#[:space:]]+).*/\1/' <<<"$uline")
		if [ -n "$user" ]; then admin_set["$user"]=1; fi
	done < <(grep -E '^[[:alnum:]._-]+[[:space:]]+ALL\s*=\(' "$f" 2>/dev/null || true)
done

# Turn admin_set into array
admin_users=()
for u in "${!admin_set[@]}"; do
	admin_users+=("$u")
done

# Optionally write current admin list to baseline file (useful for bootstrapping)
if [ -n "$WRITE_BASELINE" ]; then
	printf '%s
' "${admin_users[@]}" > "$WRITE_BASELINE"
fi

# CONTROL 3 — VALIDATION AGAINST BASELINE (if provided)
authorized_admins=()
unauthorized_admins=()
missing_admins=()
if [ -n "$BASELINE_FILE" ] && [ -r "$BASELINE_FILE" ]; then
	mapfile -t authorized_admins < <(sed -E 's/#.*//' "$BASELINE_FILE" | sed '/^\s*$/d')
	# build sets
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

# CONTROL 4 — DETECTION OF ANOMALIES
anomalies=()
highest_severity=0

add_anomaly(){
	local sev="$1"; shift; local msg="$*"
	anomalies+=("$sev: $msg")
	if [ "$sev" = "CRITICAL" ]; then highest_severity=2; fi
	if [ "$sev" = "WARNING" ] && [ "$highest_severity" -lt 1 ]; then highest_severity=1; fi
}

# 1) UID 0 besides root
uids0=()
for line in "${PASSWD_LINES[@]}"; do
	IFS=: read -r username passwd uid gid gecos home shell <<<"$line"
	if [ "$uid" = "0" ]; then uids0+=("$username"); fi
done
if [ "${#uids0[@]}" -gt 1 ]; then
	add_anomaly "CRITICAL" "Multiple UID 0 accounts: ${uids0[*]}"
fi

# 2) Too many admin users
if [ "${#admin_users[@]}" -gt "$ADMIN_MAX" ]; then
	add_anomaly "WARNING" "${#admin_users[@]} admin accounts (threshold $ADMIN_MAX)"
fi

# 3) System accounts with interactive shell
for line in "${PASSWD_LINES[@]}"; do
	IFS=: read -r username passwd uid gid gecos home shell <<<"$line"
	if is_interactive_shell "$shell"; then
		# Consider a system account interactive anomaly only when UID is below human threshold
		# and it's not root (root is expected to have UID 0 and may have interactive shell)
		if (( uid < HUMAN_UID_MIN )) && [ "$username" != "root" ]; then
			add_anomaly "WARNING" "System account with interactive shell: $username (UID $uid, shell $shell)"
		fi
	fi
done

# 4) Accounts without password (needs /etc/shadow)
if [ -r /etc/shadow ]; then
	while IFS=: read -r user pass rest; do
		if [ -z "$pass" ]; then
			add_anomaly "CRITICAL" "Account with empty password field in /etc/shadow: $user"
		fi
	done < /etc/shadow
else
	if [ "$(id -u)" -ne 0 ]; then
		add_anomaly "INFO" "Running unprivileged; skipping /etc/shadow checks"
	else
		add_anomaly "WARNING" "Cannot read /etc/shadow; skipping password checks"
	fi
fi

 
log_line(){
	local sev="$1"; shift; local msg="$*"
	printf '%s [%s] %s\n' "$(date --rfc-3339=seconds 2>/dev/null || date +"%Y-%m-%d %H:%M:%S")" "$sev" "$msg"
}

# Output logs: uma linha por controle/anomalia
log_line "INFO" "Human users: ${#human_users[@]}"
if [ ${#human_users[@]} -gt 0 ]; then
	log_line "INFO" "Human user list: ${human_users[*]}"
fi
log_line "INFO" "Admin users: ${#admin_users[@]}"
if [ ${#admin_users[@]} -gt 0 ]; then
	log_line "INFO" "Admin user list: ${admin_users[*]}"
fi
if [ -n "$BASELINE_FILE" ]; then
	log_line "INFO" "Unauthorized admins: ${#unauthorized_admins[@]}"
	log_line "INFO" "Missing expected admins: ${#missing_admins[@]}"
fi
log_line "INFO" "Anomalies: ${#anomalies[@]}"
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