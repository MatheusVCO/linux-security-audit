#!/bin/bash

SCRIPT_NAME="network"

# helpers: usa o log central se disponível (wrapper seguro)
net_log() {
	# Usage: net_log SEVERITY message...
	# SEVERITY: OK, INFO, WARNING, CRITICAL
	# Uso: net_log SEVERITY mensagem...
	# SEVERITY: OK, INFO, WARNING, CRITICAL
	local sev="$1"; shift
	local raw="$*"
	if [ -z "$sev" ]; then
		sev="INFO"
	fi

	# obtém timestamp ISO com timezone, substitui T por espaço
	ts=$(date --iso-8601=seconds 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")
	ts=${ts/T/ }

	out="$ts [${sev}] $raw"

	if type -t log >/dev/null 2>&1; then
		def=$(declare -f log 2>/dev/null || true)
		if echo "$def" | grep -q "net_log"; then
			echo "$out"
		else
			log "$out"
		fi
	else
		echo "$out"
	fi
}

set_max_severity() {
	# severidade: OK=0, INFO=1, WARNING=2, CRITICAL=3
	local sev_name="$1"
	case "$sev_name" in
		OK) sev=0 ;; INFO) sev=1 ;; WARNING) sev=2 ;; CRITICAL) sev=3 ;; *) sev=0 ;;
	esac
	if [ -z "${NETWORK_MAX_SEVERITY+x}" ] || [ "$sev" -gt "$NETWORK_MAX_SEVERITY" ]; then
		NETWORK_MAX_SEVERITY=$sev
		NETWORK_MAX_SEVERITY_NAME=$sev_name
	fi
}

report_exit_code() {
	case "$NETWORK_MAX_SEVERITY" in
		0|"") return 0 ;;
		1) return 0 ;;
		2) return 1 ;;
		3) return 2 ;;
		*) return 0 ;;
	esac
}

#######################
# CONTROLE 1: PORTAS EM ESCUTA
check_listening_ports() {
	net_log INFO "${SCRIPT_NAME^^}: Verificando sockets em escuta..."
	if [ ${#SS_SNAPSHOT[@]} -gt 0 ]; then
		listen_lines=("${SS_SNAPSHOT[@]}")
	else
		mapfile -t listen_lines < <(ss -tulnpo 2>/dev/null || ss -tuln 2>/dev/null)
	fi
	if [ ${#listen_lines[@]} -eq 0 ]; then
		net_log WARNING "${SCRIPT_NAME^^}: Não foi possível obter sockets em escuta"
		set_max_severity WARNING
		return
	fi

	for line in "${listen_lines[@]}"; do
		if [[ "$line" =~ LISTEN ]]; then
			addr_port=$(echo "$line" | awk '{print $5}')
			proc=$(echo "$line" | grep -o "users:(.*)" || true)
			net_log INFO "${SCRIPT_NAME^^}: Escutando: $addr_port $proc"
			# detecção de mudança: se esta entrada não estava na linha de base anterior, sinalizar
			if [ ${#OLD_SS_SNAPSHOT[@]} -gt 0 ]; then
				found=0
				for old in "${OLD_SS_SNAPSHOT[@]}"; do
					if [ "$old" = "$line" ]; then
						found=1; break
					fi
				done
				if [ $found -eq 0 ]; then
					net_log WARNING "${SCRIPT_NAME^^}: Novo socket em escuta desde a última execução: $addr_port $proc"
					set_max_severity WARNING
				fi
			fi
		fi
	done
	set_max_severity OK
}

#######################
# CONTROLE 2: ESCUTA EM TODAS AS INTERFACES
check_listen_all_interfaces() {
	net_log INFO "${SCRIPT_NAME^^}: Verificando serviços escutando em todas as interfaces..."
	if [ ${#SS_SNAPSHOT[@]} -gt 0 ]; then
		lines=("${SS_SNAPSHOT[@]}")
	else
		mapfile -t lines < <(ss -tulnpo 2>/dev/null || ss -tuln 2>/dev/null)
	fi
	for line in "${lines[@]}"; do
		if [[ "$line" =~ LISTEN ]]; then
			addr_port=$(echo "$line" | awk '{print $5}')
			ip_part=${addr_port%:*}
			# normaliza formas reduzidas de IPv6
			if [ "$ip_part" = "0.0.0.0" ] || [ "$ip_part" = "::" ] || [ "$ip_part" = ":::" ]; then
				proc=$(echo "$line" | grep -o "users:(.*)" || true)
				net_log WARNING "${SCRIPT_NAME^^}: Serviço escutando em todas as interfaces: $addr_port $proc"
				set_max_severity WARNING
			fi
		fi
	done
}

#######################
# CONTROLE 3: STATUS DO FIREWALL
check_firewall() {
	net_log INFO "${SCRIPT_NAME^^}: Verificando status do firewall..."
	local fw_active=0

	if command -v ufw >/dev/null 2>&1; then
		status=$(ufw status verbose 2>/dev/null || true)
		if echo "$status" | grep -qi "Status: active"; then
			net_log INFO "${SCRIPT_NAME^^}: UFW ativo"
			fw_active=1
		fi
	fi

	if [ $fw_active -eq 0 ] && command -v firewall-cmd >/dev/null 2>&1; then
		if firewall-cmd --state &>/dev/null; then
			net_log INFO "${SCRIPT_NAME^^}: firewalld ativo"
			fw_active=1
		fi
	fi

	if [ $fw_active -eq 0 ]; then
		# Check nft/iptables rules
		if command -v nft >/dev/null 2>&1; then
			if nft list ruleset 2>/dev/null | grep -q "filter"; then
				net_log INFO "${SCRIPT_NAME^^}: Regras nftables encontradas"
				fw_active=1
			fi
		fi
	fi

	if [ $fw_active -eq 0 ]; then
		if iptables-save 2>/dev/null | grep -q "-A"; then
			net_log INFO "${SCRIPT_NAME^^}: Regras iptables encontradas"
			fw_active=1
		fi
	fi

	if [ $fw_active -eq 0 ]; then
		net_log CRITICAL "${SCRIPT_NAME^^}: Nenhum firewall detectado ou sem regras configuradas"
		set_max_severity CRITICAL
	else
		net_log OK "${SCRIPT_NAME^^}: Firewall ativo/configurado"
		set_max_severity OK
	fi
}

# Verifica política padrão do firewall (checagem básica de efetividade)
check_firewall_policy() {
	net_log INFO "${SCRIPT_NAME^^}: Verificando políticas padrão do firewall..."
	# UFW
	if command -v ufw >/dev/null 2>&1; then
		out=$(ufw status verbose 2>/dev/null || true)
		if echo "$out" | grep -qi "Default: deny" || echo "$out" | grep -qi "Default: reject"; then
			net_log INFO "${SCRIPT_NAME^^}: Política padrão de entrada do UFW é restritiva"
		else
			net_log WARNING "${SCRIPT_NAME^^}: Política padrão de entrada do UFW é permissiva ou não é deny"
			set_max_severity WARNING
		fi
		return
	fi

	# nft
	if command -v nft >/dev/null 2>&1; then
		# check for a filter table with input chain policy
		# Avoid using grep -A; some greps (BusyBox) complain about it.
		policy=$(nft list ruleset 2>/dev/null |
			awk '/chain input/ {found=1; next}
			 found && /policy/ {print; exit}' |
			grep -o "policy (accept|drop|reject)" || true)
		if echo "$policy" | grep -qi "drop\|reject"; then
			net_log INFO "${SCRIPT_NAME^^}: Política de input do nftables é restritiva"
		else
			net_log WARNING "${SCRIPT_NAME^^}: Política de input do nftables permissiva ou não definida"
			set_max_severity WARNING
		fi
		return
	fi

	# iptables
	if command -v iptables >/dev/null 2>&1; then
		pol=$(iptables -L INPUT -n 2>/dev/null | head -n1 || true)
		if echo "$pol" | grep -qi "policy DROP\|policy REJECT"; then
			net_log INFO "${SCRIPT_NAME^^}: Política INPUT do iptables é restritiva"
		else
			net_log WARNING "${SCRIPT_NAME^^}: Política INPUT do iptables permissiva (ACCEPT)"
			set_max_severity WARNING
		fi
		return
	fi

	net_log INFO "${SCRIPT_NAME^^}: Não foi possível determinar política padrão do firewall (ferramenta não disponível)"
}

#######################
# CONTROL 4: ACTIVE NETWORK INTERFACES
check_interfaces() {
	net_log INFO "${SCRIPT_NAME^^}: Verificando interfaces de rede ativas..."
	# lista interfaces UP excluindo lo
	mapfile -t if_lines < <(ip -brief link show up | awk '!/LOOPBACK/ {print}')
	for line in "${if_lines[@]}"; do
		iface=$(echo "$line" | awk '{print $1}')
		if [ "$iface" != "lo" ]; then
			state=$(echo "$line" | awk '{print $2}')
			addrs=$(ip -o -f inet addr show "$iface" | awk '{print $4}' | paste -s -d"," -)
			net_log INFO "${SCRIPT_NAME^^}: Interface $iface: $state enderecos=$addrs"
		fi
	done
	set_max_severity OK
}

#######################
# CONTROL 5: SENSITIVE SERVICES EXPOSED
check_sensitive_services() {
	net_log INFO "${SCRIPT_NAME^^}: Verificando exposição de serviços sensíveis..."
	declare -A sensitive_ports=( [22]=ssh [3306]=mysql [5432]=postgres [27017]=mongodb [6379]=redis [9200]=elasticsearch )
	if [ ${#SS_SNAPSHOT[@]} -gt 0 ]; then
		ss_lines=("${SS_SNAPSHOT[@]}")
	else
		mapfile -t ss_lines < <(ss -tulnpo 2>/dev/null || ss -tuln 2>/dev/null)
	fi
	for line in "${ss_lines[@]}"; do
		if echo "$line" | grep -q "LISTEN"; then
			addr_port=$(echo "$line" | awk '{print $5}')
			ip_part=${addr_port%:*}
			port_part=${addr_port##*:}
			if [[ -n "${sensitive_ports[$port_part]}" ]]; then
				# normalize IPv6 localhost forms
				if [[ "$ip_part" != "127.0.0.1" && "$ip_part" != "::1" && "$ip_part" != "[::1]" ]]; then
					svc=${sensitive_ports[$port_part]}
					if [ "$port_part" = "22" ]; then
						net_log WARNING "${SCRIPT_NAME^^}: SSH ($svc) exposto em $ip_part:$port_part"
						set_max_severity WARNING
					else
						net_log CRITICAL "${SCRIPT_NAME^^}: Serviço sensível $svc exposto em $ip_part:$port_part"
						set_max_severity CRITICAL
					fi
				fi
			fi
		fi
	done
}

#######################
# Main entry for this module
run_checks() {
	NETWORK_MAX_SEVERITY=0
	NETWORK_MAX_SEVERITY_NAME=OK
	# take snapshots of dynamic state once to keep checks consistent
	mapfile -t SS_SNAPSHOT < <(ss -tulnpo 2>/dev/null || ss -tuln 2>/dev/null)
	# persiste snapshot baseline para detecção de mudanças
	baseline_file="report/network_ss_baseline.txt"
	mkdir -p "$(dirname "$baseline_file")"
	if [ -f "$baseline_file" ]; then
		mapfile -t OLD_SS_SNAPSHOT < "$baseline_file"
	else
		OLD_SS_SNAPSHOT=()
	fi
	# grava snapshot atual (atômico)
	printf "%s\n" "${SS_SNAPSHOT[@]}" > "$baseline_file.tmp" && mv "$baseline_file.tmp" "$baseline_file"

	check_listening_ports
	check_listen_all_interfaces
	check_firewall
	check_firewall_policy
	check_interfaces
	check_sensitive_services

	# Log final usando a severidade máxima como parâmetro
	net_log "$NETWORK_MAX_SEVERITY_NAME" "${SCRIPT_NAME^^}: severidade final = ${NETWORK_MAX_SEVERITY_NAME:-OK} (code=$NETWORK_MAX_SEVERITY)"
	report_exit_code
}

# If script is executed directly, run checks and exit accordingly
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	run_checks
	exit_code=$?
	exit $exit_code
fi
