
#!/bin/bash

############################################################
# COMMON UTILITY FUNCTIONS
# (Anteriormente em lib/common.sh - agora integrado)
############################################################

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Detect OS type
detect_os() {
    case "$(uname -s)" in
        Linux*)     echo "Linux";;
        Darwin*)    echo "macOS";;
        CYGWIN*)    echo "Cygwin";;
        MINGW*)     echo "MinGw";;
        *)          echo "UNKNOWN";;
    esac
}

# Check if running as root
is_root() {
    [[ $EUID -eq 0 ]]
}

# Print error message and exit
error_exit() {
    echo "ERROR: $1" >&2
    exit 1
}

# Print warning message
warn() {
    echo "WARNING: $1" >&2
}

# Print info message
info() {
    echo "INFO: $1"
}

# Retry a command with exponential backoff
retry() {
    local max_attempts=5
    local timeout=1
    local attempt=1
    
    while (( attempt <= max_attempts )); do
        if "$@"; then
            return 0
        fi
        
        echo "Attempt $attempt failed. Retrying in ${timeout}s..." >&2
        sleep "$timeout"
        timeout=$((timeout * 2))
        attempt=$((attempt + 1))
    done
    
    return 1
}

# Check if port is in use
is_port_in_use() {
    local port=$1
    command_exists lsof && lsof -Pi ":$port" -sTCP:LISTEN -t >/dev/null 2>&1
}

# Get absolute path
get_abs_path() {
    cd "$(dirname "$1")" && pwd -P && cd - >/dev/null || return 1
}

# Validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    fi
    return 1
}

# Function to check if value is in array
in_array(){
	local v pat
	v="$1"; shift
	for pat in "$@"; do
		[[ "$v" == "$pat" ]] && return 0
	done
	return 1
}

############################################################
# LINUX SECURITY AUDIT - MAIN ORCHESTRATOR
#
# Objetivo:
# Executar uma auditoria completa de segurança do sistema
# Linux, consolidando resultado de múltiplos módulos.
#
# Arquitetura:
# - Sistema centralizado de logging (log_entry)
# - Execução de módulos: network, services, ssh, users
# - Consolidação de severidade (máxima entre módulos)
# - Geração de relatório estruturado
#
# Uso:
# ./main.sh [--json] [--report-dir DIR]
# ./main.sh [--network] [--services] [--ssh] [--user]
############################################################

set -eu

# PATH explícito para execução não interativa (cron/systemd timers)
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
export PATH

############################################################
# CONFIGURAÇÃO GLOBAL
############################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="${SCRIPT_DIR}/report"
OUTPUT_FORMAT="text"  # text ou json
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${REPORT_DIR}/audit_${TIMESTAMP}.log"
SUMMARY_FILE="${REPORT_DIR}/audit_${TIMESTAMP}_summary.txt"

# Arrays para consolidar resultados
declare -A MODULE_RESULTS
declare -A MODULE_SEVERITY
declare -A MODULE_LOGS

# Severidade global: 0=OK, 1=INFO, 2=WARNING, 3=CRITICAL
GLOBAL_SEVERITY=0
GLOBAL_SEVERITY_NAME="OK"

# Controle de execução modular
RUN_NETWORK=1
RUN_SERVICES=1
RUN_SSH=1
RUN_USERS=1

print_usage() {
	cat <<EOF
Uso:
  ./main.sh [opções]

Opções de módulo (podem ser combinadas):
  --network            Executa apenas (ou inclui) auditoria de rede
  --services           Executa apenas (ou inclui) auditoria de serviços
  --ssh                Executa apenas (ou inclui) auditoria de SSH
  --user, --users      Executa apenas (ou inclui) auditoria de usuários
  --all                Executa todos os módulos

Outras opções:
  --json               Define OUTPUT_FORMAT=json
  --report-dir DIR     Define diretório de saída dos relatórios
  -h, --help           Exibe esta ajuda
EOF
}

parse_args() {
	local specific_module_selected=0

	while [ "$#" -gt 0 ]; do
		case "$1" in
			--network|--services|--ssh|--user|--users)
				if [ "$specific_module_selected" -eq 0 ]; then
					# Ao selecionar o primeiro módulo explícito, desativa todos.
					RUN_NETWORK=0
					RUN_SERVICES=0
					RUN_SSH=0
					RUN_USERS=0
					specific_module_selected=1
				fi
				case "$1" in
					--network) RUN_NETWORK=1 ;;
					--services) RUN_SERVICES=1 ;;
					--ssh) RUN_SSH=1 ;;
					--user|--users) RUN_USERS=1 ;;
				esac
				shift
				;;
			--all)
				RUN_NETWORK=1
				RUN_SERVICES=1
				RUN_SSH=1
				RUN_USERS=1
				specific_module_selected=1
				shift
				;;
			--json)
				OUTPUT_FORMAT="json"
				shift
				;;
			--report-dir)
				[ "$#" -lt 2 ] && error_exit "A opção --report-dir exige um diretório"
				REPORT_DIR="$2"
				shift 2
				;;
			-h|--help)
				print_usage
				exit 0
				;;
			*)
				echo "ERROR: Opção inválida: $1" >&2
				print_usage >&2
				exit 1
				;;
		esac
	done

	# Recalcula caminhos de saída caso report-dir tenha sido alterado.
	LOG_FILE="${REPORT_DIR}/audit_${TIMESTAMP}.log"
	SUMMARY_FILE="${REPORT_DIR}/audit_${TIMESTAMP}_summary.txt"
}

mark_module_skipped() {
	local module_key="$1"
	local module_log_key="$2"
	MODULE_SEVERITY["$module_key"]=-1
	MODULE_LOGS["$module_log_key"]="Módulo não executado (SKIPPED)"
	log_entry "INFO" "MAIN" "Módulo $module_key não executado (SKIPPED)"
}

############################################################
# FUNÇÕES AUXILIARES DE INICIALIZAÇÃO
############################################################

setup_environment() {
	# Cria/valida diretório de saída
	mkdir -p "$REPORT_DIR"
	
	# Inicializa arquivo de log
	{
		echo "================================================================================"
		echo "AUDITORIA DE SEGURANÇA LINUX - $(date '+%Y-%m-%d %H:%M:%S')"
		echo "================================================================================"
		echo ""
	} > "$LOG_FILE"
}

############################################################
# SISTEMA CENTRAL DE LOGGING
#
# Padrão: timestamp [SEVERIDADE] [SEÇÃO] mensagem
# Severidades: OK, INFO, WARNING, CRITICAL
# Seções: NETWORK, SERVICES, SSH, USERS, MAIN
############################################################

log_entry() {
	local severity="$1"
	local section="$2"
	shift 2
	local message="$*"
	
	# Valida severidade
	case "$severity" in
		OK|INFO|WARNING|CRITICAL) ;;
		*) severity="INFO" ;;
	esac
	
	# Formata timestamp
	local ts
	ts=$(date '+%Y-%m-%d %H:%M:%S')
	
	# Cria entrada de log
	local log_entry="[$ts] [$severity] [$section] $message"
	
	# Escreve no arquivo de log
	echo "$log_entry" >> "$LOG_FILE"
	
	# Exibe no console também
	echo "$log_entry"
}

############################################################
# FUNÇÕES DE SEVERIDADE
############################################################

update_global_severity() {
	local module="$1"
	local severity_name="$2"
	
	# Converte nome em número
	local severity=0
	case "$severity_name" in
		OK) severity=0 ;;
		INFO) severity=1 ;;
		WARNING) severity=2 ;;
		CRITICAL) severity=3 ;;
		*) severity=0 ;;
	esac
	
	# Armazena resultado do módulo
	MODULE_SEVERITY["$module"]=$severity
	
	# Atualiza severidade global se necessário
	if [ "$severity" -gt "$GLOBAL_SEVERITY" ]; then
		GLOBAL_SEVERITY=$severity
		case "$severity" in
			0) GLOBAL_SEVERITY_NAME="OK" ;;
			1) GLOBAL_SEVERITY_NAME="INFO" ;;
			2) GLOBAL_SEVERITY_NAME="WARNING" ;;
			3) GLOBAL_SEVERITY_NAME="CRITICAL" ;;
		esac
	fi
}

############################################################
# MÓDULO: NETWORK AUDIT
############################################################

# NETWORK HELPERS
net_log() {
	local sev="$1"; shift
	local raw="$*"
	if [ -z "$sev" ]; then
		sev="INFO"
	fi

	ts=$(date --iso-8601=seconds 2>/dev/null || date -u "+%Y-%m-%dT%H:%M:%SZ")
	ts=${ts/T/ }
	case "$sev" in
		CRITICAL)
			log_entry "CRITICAL" "NETWORK" "$raw" ;;
		WARNING)
			log_entry "WARNING" "NETWORK" "$raw" ;;
		INFO|OK)
			log_entry "INFO" "NETWORK" "$raw" ;;
		*)
			echo "$ts [$sev] $raw" ;;
	esac
}

net_set_max_severity() {
	local sev_name="$1"
	case "$sev_name" in
		OK) sev=0 ;; INFO) sev=1 ;; WARNING) sev=2 ;; CRITICAL) sev=3 ;; *) sev=0 ;;
	esac
	if [ -z "${NETWORK_MAX_SEVERITY+x}" ] || [ "$sev" -gt "$NETWORK_MAX_SEVERITY" ]; then
		NETWORK_MAX_SEVERITY=$sev
		NETWORK_MAX_SEVERITY_NAME=$sev_name
	fi
}

net_check_listening_ports() {
	net_log "INFO" "${SCRIPT_NAME^^}: Verificando sockets em escuta..."
	if [ ${#SS_SNAPSHOT[@]} -gt 0 ]; then
		listen_lines=("${SS_SNAPSHOT[@]}")
	else
		mapfile -t listen_lines < <(ss -tulnpo 2>/dev/null || ss -tuln 2>/dev/null)
	fi
	if [ ${#listen_lines[@]} -eq 0 ]; then
		net_log "WARNING" "${SCRIPT_NAME^^}: Não foi possível obter sockets em escuta"
		net_set_max_severity "WARNING"
		return
	fi

	for line in "${listen_lines[@]}"; do
		if [[ "$line" =~ LISTEN ]]; then
			addr_port=$(echo "$line" | awk '{print $5}')
			proc=$(echo "$line" | grep -o "users:(.*)" || true)
			net_log "INFO" "${SCRIPT_NAME^^}: Escutando: $addr_port $proc"
			if [ ${#OLD_SS_SNAPSHOT[@]} -gt 0 ]; then
				found=0
				for old in "${OLD_SS_SNAPSHOT[@]}"; do
					if [ "$old" = "$line" ]; then
						found=1; break
					fi
				done
				if [ $found -eq 0 ]; then
					net_log "WARNING" "${SCRIPT_NAME^^}: Novo socket em escuta desde a última execução: $addr_port $proc"
					net_set_max_severity "WARNING"
				fi
			fi
		fi
	done
	net_set_max_severity "OK"
}

net_check_listen_all_interfaces() {
	net_log "INFO" "${SCRIPT_NAME^^}: Verificando serviços escutando em todas as interfaces..."
	if [ ${#SS_SNAPSHOT[@]} -gt 0 ]; then
		lines=("${SS_SNAPSHOT[@]}")
	else
		mapfile -t lines < <(ss -tulnpo 2>/dev/null || ss -tuln 2>/dev/null)
	fi
	for line in "${lines[@]}"; do
		if [[ "$line" =~ LISTEN ]]; then
			addr_port=$(echo "$line" | awk '{print $5}')
			ip_part=${addr_port%:*}
			if [ "$ip_part" = "0.0.0.0" ] || [ "$ip_part" = "::" ] || [ "$ip_part" = ":::" ]; then
				proc=$(echo "$line" | grep -o "users:(.*)" || true)
				net_log "WARNING" "${SCRIPT_NAME^^}: Serviço escutando em todas as interfaces: $addr_port $proc"
				net_set_max_severity "WARNING"
			fi
		fi
	done
}

net_check_firewall() {
	net_log "INFO" "${SCRIPT_NAME^^}: Verificando status do firewall..."
	local fw_active=0

	if command_exists ufw >/dev/null 2>&1; then
		status=$(ufw status verbose 2>/dev/null || true)
		if echo "$status" | grep -qi "Status: active"; then
			net_log "INFO" "${SCRIPT_NAME^^}: UFW ativo"
			fw_active=1
		fi
	fi

	if [ $fw_active -eq 0 ] && command_exists firewall-cmd >/dev/null 2>&1; then
		if firewall-cmd --state &>/dev/null; then
			net_log "INFO" "${SCRIPT_NAME^^}: firewalld ativo"
			fw_active=1
		fi
	fi

	if [ $fw_active -eq 0 ]; then
		if command_exists nft >/dev/null 2>&1; then
			if nft list ruleset 2>/dev/null | grep -q "filter"; then
				net_log "INFO" "${SCRIPT_NAME^^}: Regras nftables encontradas"
				fw_active=1
			fi
		fi
	fi

	if [ $fw_active -eq 0 ]; then
		if command_exists iptables-save >/dev/null 2>&1 && iptables-save 2>/dev/null | grep -q -- '^-A '; then
			net_log "INFO" "${SCRIPT_NAME^^}: Regras iptables encontradas"
			fw_active=1
		fi
	fi

	if [ $fw_active -eq 0 ]; then
		net_log "CRITICAL" "${SCRIPT_NAME^^}: Nenhum firewall detectado ou sem regras configuradas"
		net_set_max_severity "CRITICAL"
	else
		net_log "OK" "${SCRIPT_NAME^^}: Firewall ativo/configurado"
		net_set_max_severity "OK"
	fi
}

net_check_firewall_policy() {
	net_log "INFO" "${SCRIPT_NAME^^}: Verificando políticas padrão do firewall..."
	if command_exists ufw >/dev/null 2>&1; then
		out=$(ufw status verbose 2>/dev/null || true)
		if echo "$out" | grep -qi "Default: deny" || echo "$out" | grep -qi "Default: reject"; then
			net_log "INFO" "${SCRIPT_NAME^^}: Política padrão de entrada do UFW é restritiva"
		else
			net_log "WARNING" "${SCRIPT_NAME^^}: Política padrão de entrada do UFW é permissiva ou não é deny"
			net_set_max_severity "WARNING"
		fi
		return
	fi

	if command_exists nft >/dev/null 2>&1; then
		policy=$(nft list ruleset 2>/dev/null |
			awk '/chain input/ {found=1; next}
			 found && /policy/ {print; exit}' |
			grep -o "policy (accept|drop|reject)" || true)
		if echo "$policy" | grep -qi "drop\|reject"; then
			net_log "INFO" "${SCRIPT_NAME^^}: Política de input do nftables é restritiva"
		else
			net_log "WARNING" "${SCRIPT_NAME^^}: Política de input do nftables permissiva ou não definida"
			net_set_max_severity "WARNING"
		fi
		return
	fi

	if command_exists iptables >/dev/null 2>&1; then
		pol=$(iptables -L INPUT -n 2>/dev/null | head -n1 || true)
		if echo "$pol" | grep -qi "policy DROP\|policy REJECT"; then
			net_log "INFO" "${SCRIPT_NAME^^}: Política INPUT do iptables é restritiva"
		else
			net_log "WARNING" "${SCRIPT_NAME^^}: Política INPUT do iptables permissiva (ACCEPT)"
			net_set_max_severity "WARNING"
		fi
		return
	fi

	net_log "INFO" "${SCRIPT_NAME^^}: Não foi possível determinar política padrão do firewall (ferramenta não disponível)"
}

net_check_interfaces() {
	net_log "INFO" "${SCRIPT_NAME^^}: Verificando interfaces de rede ativas..."
	mapfile -t if_lines < <(ip -brief link show up | awk '!/LOOPBACK/ {print}')
	for line in "${if_lines[@]}"; do
		iface=$(echo "$line" | awk '{print $1}')
		if [ "$iface" != "lo" ]; then
			state=$(echo "$line" | awk '{print $2}')
			addrs=$(ip -o -f inet addr show "$iface" | awk '{print $4}' | paste -s -d"," -)
			net_log "INFO" "${SCRIPT_NAME^^}: Interface $iface: $state enderecos=$addrs"
		fi
	done
	net_set_max_severity "OK"
}

net_check_sensitive_services() {
	net_log "INFO" "${SCRIPT_NAME^^}: Verificando exposição de serviços sensíveis..."
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
			if [[ -n "${sensitive_ports[$port_part]:-}" ]]; then
				if [[ "$ip_part" != "127.0.0.1" && "$ip_part" != "::1" && "$ip_part" != "[::1]" ]]; then
					svc=${sensitive_ports[$port_part]}
					if [ "$port_part" = "22" ]; then
						net_log "WARNING" "${SCRIPT_NAME^^}: SSH ($svc) exposto em $ip_part:$port_part"
						net_set_max_severity "WARNING"
					else
						net_log "CRITICAL" "${SCRIPT_NAME^^}: Serviço sensível $svc exposto em $ip_part:$port_part"
						net_set_max_severity "CRITICAL"
					fi
				fi
			fi
		fi
	done
}

run_network_audit() {
	log_entry "INFO" "MAIN" "========== INICIANDO AUDITORIA DE REDE =========="
	
	SCRIPT_NAME="network"
	NETWORK_MAX_SEVERITY=0
	NETWORK_MAX_SEVERITY_NAME=OK
	
	# Snapshots de estado dinâmico
	mapfile -t SS_SNAPSHOT < <(ss -tulnpo 2>/dev/null || ss -tuln 2>/dev/null)
	baseline_file="${REPORT_DIR}/network_ss_baseline.txt"
	mkdir -p "$(dirname "$baseline_file")"
	if [ -f "$baseline_file" ]; then
		mapfile -t OLD_SS_SNAPSHOT < "$baseline_file"
	else
		OLD_SS_SNAPSHOT=()
	fi
	printf "%s\n" "${SS_SNAPSHOT[@]}" > "$baseline_file.tmp" && mv -f "$baseline_file.tmp" "$baseline_file"

	net_check_listening_ports
	net_check_listen_all_interfaces
	net_check_firewall
	net_check_firewall_policy
	net_check_interfaces
	net_check_sensitive_services

	net_log "INFO" "${SCRIPT_NAME^^}: severidade final = ${NETWORK_MAX_SEVERITY_NAME:-OK} (code=$NETWORK_MAX_SEVERITY)"
	
	# Armazena resultados
	MODULE_LOGS["network"]="Auditoria de REDE concluída"
	update_global_severity "NETWORK" "$NETWORK_MAX_SEVERITY_NAME"
	log_entry "$NETWORK_MAX_SEVERITY_NAME" "MAIN" "Auditoria de REDE concluída com severidade: $NETWORK_MAX_SEVERITY_NAME"
	log_entry "INFO" "MAIN" ""
}

############################################################
# MÓDULO: SERVICES AUDIT
############################################################

# Baseline de serviços esperados
EXPECTED_ACTIVE_SERVICES=("systemd-journald" "systemd-logind" "systemd-udevd")
SENSITIVE_SERVICES=("apache2" "nginx" "mysql" "postgresql" "mongodb" "redis" "openssh-server" "sshd" "docker" "docker.service" "smbd" "nfs-server")
CRITICAL_SERVICES=("apache2" "nginx" "mysql" "postgresql" "sshd" "openssh-server" "docker" "docker.service")

svc_log() {
	local sev="$1"; shift
	local raw="$*"
	if [ -z "$sev" ]; then
		sev="INFO"
	fi
	log_entry "$sev" "SERVICES" "$raw"
}

svc_set_max_severity() {
	local sev_name="$1"
	local sev
	case "$sev_name" in
		OK) sev=0 ;; INFO) sev=1 ;; WARNING) sev=2 ;; CRITICAL) sev=3 ;; *) sev=0 ;;
	esac
	if [ -z "${SERVICES_MAX_SEVERITY+x}" ] || [ "$sev" -gt "$SERVICES_MAX_SEVERITY" ]; then
		SERVICES_MAX_SEVERITY=$sev
		SERVICES_MAX_SEVERITY_NAME=$sev_name
	fi
}

svc_is_sensitive_service() {
	local service="$1"
	for sensitive in "${SENSITIVE_SERVICES[@]}"; do
		if [[ "$service" == *"$sensitive"* ]]; then
			return 0
		fi
	done
	return 1
}

svc_is_critical_service() {
	local service="$1"
	for critical in "${CRITICAL_SERVICES[@]}"; do
		if [[ "$service" == *"$critical"* ]]; then
			return 0
		fi
	done
	return 1
}

svc_check_active_services() {
	svc_log "INFO" "SERVICES: Verificando serviços ativos..."

	mapfile -t active_services < <(systemctl list-units --type=service --state=active --no-pager --plain 2>/dev/null | grep -v "^UNIT " | grep -v "^[0-9].*loaded" | awk '{print $1}' | grep -v "^$" | sed 's/\.service$//')

	if [ ${#active_services[@]} -eq 0 ]; then
		svc_log "WARNING" "SERVICES: Não foi possível obter lista de serviços ativos"
		svc_set_max_severity "WARNING"
		return
	fi

	svc_log "INFO" "SERVICES: Encontrados ${#active_services[@]} serviços ativos"
	
	for service in "${active_services[@]}"; do
		if [[ "$service" =~ ^(systemd|user@|dbus|getty) ]]; then
			svc_log "INFO" "SERVICES: Serviço do sistema ativo: $service"
			continue
		fi

		found_in_baseline=0
		for expected in "${EXPECTED_ACTIVE_SERVICES[@]}"; do
			if [[ "$service" == "$expected" ]]; then
				found_in_baseline=1
				break
			fi
		done

		if [ $found_in_baseline -eq 1 ]; then
			svc_log "INFO" "SERVICES: Serviço esperado ativo: $service"
		else
			if svc_is_critical_service "$service"; then
				svc_log "CRITICAL" "SERVICES: Serviço CRÍTICO inesperadamente ativo: $service"
				svc_set_max_severity "CRITICAL"
			elif svc_is_sensitive_service "$service"; then
				svc_log "WARNING" "SERVICES: Serviço sensível ativo (revisar necessidade): $service"
				svc_set_max_severity "WARNING"
			else
				svc_log "INFO" "SERVICES: Serviço ativo não baseline: $service"
			fi
		fi
	done

	[ ${#active_services[@]} -gt 0 ] && svc_set_max_severity "OK"
}

svc_check_enabled_services() {
	svc_log "INFO" "SERVICES: Verificando serviços habilitados no boot..."

	mapfile -t enabled_services < <(systemctl list-unit-files --type=service --state=enabled --no-pager --plain 2>/dev/null | grep -v "^FILE" | grep -v "^[0-9].*unit files" | awk '{print $1}' | sed 's/\.service$//' | grep -v "^$")

	if [ ${#enabled_services[@]} -eq 0 ]; then
		svc_log "INFO" "SERVICES: Nenhum serviço habilitado encontrado (status: may-offline)"
		svc_set_max_severity "OK"
		return
	fi

	svc_log "INFO" "SERVICES: Encontrados ${#enabled_services[@]} serviços habilitados no boot"

	for service in "${enabled_services[@]}"; do
		if [[ "$service" =~ ^(systemd|user@|getty) ]]; then
			svc_log "INFO" "SERVICES: Serviço do sistema habilitado: $service"
			continue
		fi

		found_in_baseline=0
		for expected in "${EXPECTED_ACTIVE_SERVICES[@]}"; do
			if [[ "$service" == "$expected" ]]; then
				found_in_baseline=1
				break
			fi
		done

		if [ $found_in_baseline -eq 1 ]; then
			svc_log "INFO" "SERVICES: Serviço esperado habilitado: $service"
		else
			if svc_is_sensitive_service "$service"; then
				svc_log "WARNING" "SERVICES: Serviço sensível habilitado no boot (revisar necessidade): $service"
				svc_set_max_severity "WARNING"
			else
				svc_log "INFO" "SERVICES: Serviço não-baseline habilitado: $service"
			fi
		fi
	done

	[ ${#enabled_services[@]} -gt 0 ] && svc_set_max_severity "OK"
}

svc_check_sensitive_services() {
	svc_log "INFO" "SERVICES: Verificando presença de serviços sensíveis..."

	mapfile -t active_services < <(systemctl list-units --type=service --state=active --no-pager --plain 2>/dev/null | grep -v "^UNIT " | grep -v "^[0-9].*loaded" | awk '{print $1}' | sed 's/\.service$//' | grep -v "^$")

	local sensitive_count=0
	local critical_count=0

	for service in "${active_services[@]}"; do
		if svc_is_critical_service "$service"; then
			found_expected=0
			if [ $found_expected -eq 0 ]; then
				svc_log "CRITICAL" "SERVICES: Serviço CRÍTICO ativo sem estar no baseline: $service"
				svc_set_max_severity "CRITICAL"
				((critical_count++))
			fi
		elif svc_is_sensitive_service "$service"; then
			svc_log "WARNING" "SERVICES: Serviço sensível ativo: $service (valide se necessário)"
			svc_set_max_severity "WARNING"
			((sensitive_count++))
		fi
	done

	if [ $critical_count -gt 0 ]; then
		svc_log "INFO" "SERVICES: $critical_count serviço(s) crítico(s) ativo(s)"
	fi

	if [ $sensitive_count -gt 0 ]; then
		svc_log "INFO" "SERVICES: $sensitive_count serviço(s) sensível(is) ativo(s)"
	fi

	if [ $critical_count -eq 0 ] && [ $sensitive_count -eq 0 ]; then
		svc_log "OK" "SERVICES: Nenhum serviço sensível/crítico ativo fora do esperado"
		svc_set_max_severity "OK"
	fi
}

svc_check_failed_services() {
	svc_log "INFO" "SERVICES: Verificando serviços em estado failed..."

	mapfile -t failed_services < <(systemctl list-units --type=service --state=failed --no-pager --plain 2>/dev/null | grep -v "^UNIT " | grep -v "^[0-9].*loaded" | awk '{print $1}' | sed 's/\.service$//' | grep -v "^$")

	if [ ${#failed_services[@]} -eq 0 ]; then
		svc_log "OK" "SERVICES: Nenhum serviço em estado failed"
		svc_set_max_severity "OK"
		return
	fi

	svc_log "WARNING" "SERVICES: ${#failed_services[@]} serviço(s) em estado failed"

	for service in "${failed_services[@]}"; do
		svc_log "INFO" "SERVICES: Serviço falhando: $service"

		if svc_is_critical_service "$service"; then
			svc_log "CRITICAL" "SERVICES: Serviço CRÍTICO falhando: $service"
			svc_set_max_severity "CRITICAL"
		else
			svc_log "WARNING" "SERVICES: Serviço falhando: $service"
			svc_set_max_severity "WARNING"
		fi

		reason=$(systemctl status "$service" 2>/dev/null | grep -i "failed" | head -1 || true)
		if [ -n "$reason" ]; then
			svc_log "INFO" "SERVICES: Motivo: $reason"
		fi
	done
}

svc_check_masked_services() {
	svc_log "INFO" "SERVICES: Verificando serviços em estado 'masked'..."

	local dangerous_services=("telnet" "rsh" "rlogin" "nis")

	for service in "${dangerous_services[@]}"; do
		state=$(systemctl is-enabled "$service" 2>/dev/null || echo "not-found")
		case "$state" in
			masked)
				svc_log "OK" "SERVICES: Serviço perigoso corretamente masked: $service"
				svc_set_max_severity "OK"
				;;
			enabled|disabled|indirect|static|generated)
				if [ "$state" != "not-found" ]; then
					svc_log "WARNING" "SERVICES: Serviço perigoso NÃO está masked: $service (estado: $state)"
					svc_set_max_severity "WARNING"
				fi
				;;
		esac
	done
}

run_services_audit() {
	log_entry "INFO" "MAIN" "========== INICIANDO AUDITORIA DE SERVIÇOS =========="
	
	SERVICES_MAX_SEVERITY=0
	SERVICES_MAX_SEVERITY_NAME="OK"

	svc_check_active_services
	svc_check_enabled_services
	svc_check_sensitive_services
	svc_check_failed_services
	svc_check_masked_services

	svc_log "INFO" "SERVICES: Auditoria completa. Severidade máxima: ${SERVICES_MAX_SEVERITY_NAME}"

	MODULE_LOGS["services"]="Auditoria de SERVIÇOS concluída"
	update_global_severity "SERVICES" "$SERVICES_MAX_SEVERITY_NAME"
	log_entry "$SERVICES_MAX_SEVERITY_NAME" "MAIN" "Auditoria de SERVIÇOS concluída com severidade: $SERVICES_MAX_SEVERITY_NAME"
	log_entry "INFO" "MAIN" ""
}

############################################################
# MÓDULO: SSH AUDIT
############################################################

ssh_severity=0

ssh_set_severity() {
    local v="$1"
    if ! [[ "$v" =~ ^[0-3]$ ]]; then return 0; fi
    if [ "$v" -gt "$ssh_severity" ]; then
        ssh_severity="$v"
    fi
}

ssh_log_level_from() {
    case "$1" in
        0) echo OK;;
        1) echo INFO;;
        2) echo WARNING;;
        3) echo CRITICAL;;
        *) echo INFO;;
    esac
}

ssh_gather_sshd_config() {
    local tmp
    tmp=$(mktemp)

    if [ -f /etc/ssh/sshd_config ]; then
        if [ -r /etc/ssh/sshd_config ]; then
            sed -n 's/#.*$//; /^[[:space:]]*$/d; p' /etc/ssh/sshd_config >> "$tmp" || true
        else
            log_entry "WARNING" "SSH" "SSH: sem permissão para ler /etc/ssh/sshd_config"
        fi
    fi

    if [ -d /etc/ssh/sshd_config.d ]; then
        for f in /etc/ssh/sshd_config.d/*.conf; do
            [ -e "$f" ] || continue
            if [ -r "$f" ]; then
                sed -n 's/#.*$//; /^[[:space:]]*$/d; p' "$f" >> "$tmp" || true
            else
                log_entry "WARNING" "SSH" "SSH: sem permissão para ler $f"
            fi
        done
    fi

    cat "$tmp"
    rm -f "$tmp"
}

ssh_parse_directive() {
    local key="$1"
    awk -v k="$key" 'BEGIN{IGNORECASE=1} toupper($1)==toupper(k){v=$2} END{if(v)print v}'
}

ssh_get_effective_value() {
    local key="$1"; shift
    local explicit="$1"; shift
    case "$key" in
        PermitRootLogin) echo "${explicit:-prohibit-password}";;
        PasswordAuthentication) echo "${explicit:-yes}";;
        *) echo "${explicit:-}";;
    esac
}

run_ssh_audit() {
	log_entry "INFO" "MAIN" "========== INICIANDO AUDITORIA DE SSH =========="
	
	ssh_severity=0
	local cfg
	cfg=$(ssh_gather_sshd_config)

	# CONTROLE 1 — ROOT LOGIN REMOTO
	local explicit_prl effective_prl level_prl msg_prl

	explicit_prl=$(printf "%s" "$cfg" | ssh_parse_directive PermitRootLogin || true)
	effective_prl=$(ssh_get_effective_value PermitRootLogin "$explicit_prl")

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

	ssh_set_severity "$level_prl"
	log_entry "$(ssh_log_level_from "$level_prl")" "SSH" "$msg_prl"

	# CONTROLE 2 — AUTENTICAÇÃO POR SENHA
	local explicit_pass effective_pass level_pass msg_pass

	explicit_pass=$(printf "%s" "$cfg" | ssh_parse_directive PasswordAuthentication || true)
	effective_pass=$(ssh_get_effective_value PasswordAuthentication "$explicit_pass")

	if [ "$effective_pass" = "no" ]; then
		level_pass=0
		msg_pass="SSH: PasswordAuthentication=NO (seguro)"
	else
		level_pass=2
		msg_pass="SSH: PasswordAuthentication=YES (WARNING)"
	fi

	ssh_set_severity "$level_pass"
	log_entry "$(ssh_log_level_from "$level_pass")" "SSH" "$msg_pass"

	# CONTROLE 3 — RESTRIÇÃO DE USUÁRIOS
	local allow_users allow_groups level_allow msg_allow

	allow_users=$(printf "%s" "$cfg" | ssh_parse_directive AllowUsers || true)
	allow_groups=$(printf "%s" "$cfg" | ssh_parse_directive AllowGroups || true)

	if [ -z "$allow_users" ] && [ -z "$allow_groups" ]; then
		level_allow=1
		msg_allow="SSH: Nenhum AllowUsers/AllowGroups definido (acesso amplo)"
	else
		level_allow=0
		msg_allow="SSH: Acesso restrito configurado"
	fi

	ssh_set_severity "$level_allow"
	log_entry "$(ssh_log_level_from "$level_allow")" "SSH" "$msg_allow"

	# CONTROLE 4 — SERVIÇO SSH ATIVO
	local active=no level_srv msg_srv

	if command_exists systemctl; then
		if systemctl is-active --quiet sshd 2>/dev/null || systemctl is-active --quiet ssh 2>/dev/null; then
			active=yes
		fi
	else
		if command_exists pgrep && pgrep -x sshd >/dev/null 2>&1; then
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

	ssh_set_severity "$level_srv"
	log_entry "$(ssh_log_level_from "$level_srv")" "SSH" "$msg_srv"

	# Resumo final
	log_entry "$(ssh_log_level_from "$ssh_severity")" "SSH" \
		"SSH: severidade final = $(ssh_log_level_from "$ssh_severity") (code=$ssh_severity)"

	# Converte código para nome
	local ssh_severity_name="OK"
	case "$ssh_severity" in
		0) ssh_severity_name="OK" ;;
		1) ssh_severity_name="INFO" ;;
		2) ssh_severity_name="WARNING" ;;
		3) ssh_severity_name="CRITICAL" ;;
	esac

	MODULE_LOGS["ssh"]="Auditoria de SSH concluída"
	update_global_severity "SSH" "$ssh_severity_name"
	log_entry "$ssh_severity_name" "MAIN" "Auditoria de SSH concluída com severidade: $ssh_severity_name"
	log_entry "INFO" "MAIN" ""
}

############################################################
# MÓDULO: USERS AUDIT
############################################################

# Parâmetros e configuração
HUMAN_UID_MIN=${HUMAN_UID_MIN:-1000}
HUMAN_UID_MAX=${HUMAN_UID_MAX:-}
ADMIN_MAX=${ADMIN_MAX:-3}
USERS_BASELINE_FILE=""

SHELL_WHITELIST=(/bin/bash /bin/sh /bin/zsh /bin/ksh /usr/bin/bash /usr/bin/zsh)
NOLOGIN_PATTERNS=(/sbin/nologin /usr/sbin/nologin /bin/false /usr/bin/false)

users_is_interactive_shell(){
	local s="$1"
	in_array "$s" "${SHELL_WHITELIST[@]}"
}

run_users_audit() {
	log_entry "INFO" "MAIN" "========== INICIANDO AUDITORIA DE USUÁRIOS =========="
	
	local baseline_file="${SCRIPT_DIR}/admins.baseline"
	local users_baseline_file=""
	
	if [ -r "$baseline_file" ]; then
		users_baseline_file="$baseline_file"
		log_entry "INFO" "MAIN" "Usando baseline de administradores: $baseline_file"
	fi

	# Coleta entradas de passwd
	local PASSWD_LINES=()
	if ! command_exists getent; then
		log_entry "WARNING" "MAIN" "O comando 'getent' não está disponível."
		return 1
	fi
	mapfile -t PASSWD_LINES < <(getent passwd)

	# CONTROLE 1 — IDENTIFICAÇÃO DE USUÁRIOS HUMANOS
	local human_users=()
	for line in "${PASSWD_LINES[@]}"; do
		IFS=: read -r username passwd uid gid gecos home shell <<<"$line"
		if (( uid >= HUMAN_UID_MIN )); then
			if [ -z "$HUMAN_UID_MAX" ] || (( uid <= HUMAN_UID_MAX )); then
				if users_is_interactive_shell "$shell"; then
					if [ -n "$home" ] && [ -d "$home" ]; then
						human_users+=("$username")
					fi
				fi
			fi
		fi
	done

	# CONTROLE 2 — IDENTIFICAÇÃO DE USUÁRIOS ADMINISTRATIVOS
	declare -A admin_set=()

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

	local sudoers_files=(/etc/sudoers)
	if [ -d /etc/sudoers.d ]; then
		while IFS= read -r -d $'\0' f; do sudoers_files+=("$f"); done < <(find /etc/sudoers.d -type f -print0 2>/dev/null || true)
	fi

	for f in "${sudoers_files[@]}"; do
		[ -r "$f" ] || continue
		while read -r gline; do
			grp=$(sed -E 's/.*%([A-Za-z0-9_\-]+).*/\1/' <<<"$gline")
			if [ -n "$grp" ]; then
				members=$(getent group "$grp" | awk -F: '{print $4}')
				IFS=, read -r -a arr <<<"$members"
				for u in "${arr[@]}"; do [ -n "$u" ] && admin_set["$u"]=1; done
			fi
		done < <(grep -E '(^|[^#])%[A-Za-z0-9_\-]+' "$f" 2>/dev/null || true)

		while read -r uline; do
			user=$(sed -E 's/^([^#[:space:]]+).*/\1/' <<<"$uline")
			if [ -n "$user" ]; then admin_set["$user"]=1; fi
		done < <(grep -E '^[[:alnum:]._-]+[[:space:]]+ALL\s*=\(' "$f" 2>/dev/null || true)
	done

	local admin_users=()
	for u in "${!admin_set[@]}"; do
		admin_users+=("$u")
	done

	# CONTROLE 3 — VALIDAÇÃO CONTRA BASELINE
	local authorized_admins=()
	local unauthorized_admins=()
	local missing_admins=()
	local baseline_check_enabled=0
	local baseline_unreadable=0
	
	if [ -n "$users_baseline_file" ] && [ -r "$users_baseline_file" ]; then
		baseline_check_enabled=1
		mapfile -t authorized_admins < <(sed -E 's/#.*//' "$users_baseline_file" | sed '/^\s*$/d')
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
	elif [ -n "$users_baseline_file" ]; then
		baseline_unreadable=1
	fi

	# CONTROLE 4 — DETECÇÃO DE ANOMALIAS
	local anomalies=()
	local highest_severity=0

	add_users_anomaly(){
		local sev="$1"; shift; local msg="$*"
		anomalies+=("$sev: $msg")
		if [ "$sev" = "CRITICAL" ]; then 
			highest_severity=2
			log_entry "CRITICAL" "USERS" "$msg"
		elif [ "$sev" = "WARNING" ] && [ "$highest_severity" -lt 1 ]; then 
			highest_severity=1
			log_entry "WARNING" "USERS" "$msg"
		else
			log_entry "INFO" "USERS" "$msg"
		fi
	}

	if [ "$baseline_unreadable" -eq 1 ]; then
		add_users_anomaly "WARNING" "Arquivo baseline informado não é legível: $users_baseline_file"
	fi

	if [ "$baseline_check_enabled" -eq 1 ] && [ "${#unauthorized_admins[@]}" -gt 0 ]; then
		unauth_csv=$(IFS=, ; echo "${unauthorized_admins[*]}")
		add_users_anomaly "WARNING" "Administradores não autorizados no baseline: $unauth_csv"
	fi
	
	if [ "$baseline_check_enabled" -eq 1 ] && [ "${#missing_admins[@]}" -gt 0 ]; then
		missing_csv=$(IFS=, ; echo "${missing_admins[*]}")
		add_users_anomaly "WARNING" "Administradores esperados ausentes do baseline: $missing_csv"
	fi

	# 1) UID 0 além do root
	local uids0=()
	for line in "${PASSWD_LINES[@]}"; do
		IFS=: read -r username passwd uid gid gecos home shell <<<"$line"
		if [ "$uid" = "0" ]; then uids0+=("$username"); fi
	done
	if [ "${#uids0[@]}" -gt 1 ]; then
		add_users_anomaly "CRITICAL" "Múltiplas contas com UID 0: ${uids0[*]}"
	fi

	# 2) Excesso de contas administrativas
	if [ "${#admin_users[@]}" -gt "$ADMIN_MAX" ]; then
		add_users_anomaly "WARNING" "${#admin_users[@]} contas administrativas (limite $ADMIN_MAX)"
	fi

	# 3) System accounts with interactive shell
	for line in "${PASSWD_LINES[@]}"; do
		IFS=: read -r username passwd uid gid gecos home shell <<<"$line"
		if users_is_interactive_shell "$shell"; then
			if (( uid < HUMAN_UID_MIN )) && [ "$username" != "root" ]; then
				add_users_anomaly "WARNING" "Conta de sistema com shell interativa: $username (UID $uid, shell $shell)"
			fi
		fi
	done

	# 4) Contas sem senha
	if [ -r /etc/shadow ]; then
		while IFS=: read -r user pass rest; do
			if [ -z "$pass" ]; then
				add_users_anomaly "CRITICAL" "Conta com campo de senha vazio em /etc/shadow: $user"
			fi
		done < /etc/shadow
	else
		if [ "$(id -u)" -ne 0 ]; then
			add_users_anomaly "INFO" "Executando sem privilégios; pulando checagem de /etc/shadow"
		else
			add_users_anomaly "WARNING" "Não é possível ler /etc/shadow; pulando checagem de senhas"
		fi
	fi

	# LOG E SAÍDA
	log_entry "INFO" "USERS" "Usuários humanos: ${#human_users[@]}"
	if [ ${#human_users[@]} -gt 0 ]; then
		human_csv=$(IFS=, ; echo "${human_users[*]}")
		log_entry "INFO" "USERS" "Lista de usuários humanos: ${human_csv}"
	fi
	
	log_entry "INFO" "USERS" "Administradores: ${#admin_users[@]}"
	if [ ${#admin_users[@]} -gt 0 ]; then
		admin_csv=$(IFS=, ; echo "${admin_users[*]}")
		log_entry "INFO" "USERS" "Lista de administradores: ${admin_csv}"
	fi
	
	if [ "$baseline_check_enabled" -eq 1 ]; then
		log_entry "INFO" "USERS" "Administradores não autorizados: ${#unauthorized_admins[@]}"
		log_entry "INFO" "USERS" "Administradores esperados ausentes: ${#missing_admins[@]}"
	elif [ "$baseline_unreadable" -eq 1 ]; then
		log_entry "WARNING" "USERS" "Arquivo baseline informado não é legível: $users_baseline_file"
	fi
	
	log_entry "INFO" "USERS" "Anomalias: ${#anomalies[@]}"

	# Converte código para nome de severidade
	local users_severity_name="OK"
	case "$highest_severity" in
		0) users_severity_name="OK" ;;
		1) users_severity_name="WARNING" ;;
		2) users_severity_name="CRITICAL" ;;
	esac

	MODULE_LOGS["users"]="Auditoria de USUÁRIOS concluída"
	update_global_severity "USERS" "$users_severity_name"
	log_entry "$users_severity_name" "MAIN" "Auditoria de USUÁRIOS concluída com severidade: $users_severity_name"
	log_entry "INFO" "MAIN" ""
}

############################################################
# GERAÇÃO DE RELATÓRIO CONSOLIDADO
############################################################

generate_summary_report() {
	log_entry "INFO" "MAIN" "========== GERANDO RELATÓRIO CONSOLIDADO =========="
	
	local os_name=$(uname -s)
	local os_version=$(uname -r)
	local kernel=$(uname -a | awk '{print $3}')
	local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
	local date_report=$(date '+%d/%m/%Y')
	local time_report=$(date '+%H:%M:%S')
	local uptime=$(uptime -p 2>/dev/null || uptime | awk '{print $1, $2, $3, $4, $5}')
	
	# Contadores de severidades (extraído do log)
	local count_critical=0
	local count_warning=0
	local count_info=0
	
	if [ -f "$LOG_FILE" ]; then
		count_critical=$(grep -c "\[CRITICAL\]" "$LOG_FILE" || true)
		count_warning=$(grep -c "\[WARNING\]" "$LOG_FILE" || true)
		count_info=$(grep -c "\[INFO\]" "$LOG_FILE" || true)
	fi
	
	{
		# Cabeçalho principal
		echo "╔════════════════════════════════════════════════════════════════════════════════╗"
		echo "║                  AUDITORIA DE SEGURANÇA LINUX - RELATÓRIO FINAL               ║"
		echo "╚════════════════════════════════════════════════════════════════════════════════╝"
		echo ""
		
		# Informações gerais
		echo "┌─ INFORMAÇÕES GERAIS ─────────────────────────────────────────────────────────┐"
		echo "│"
		printf "│  %-20s: %s\n" "Data" "$date_report"
		printf "│  %-20s: %s\n" "Hora" "$time_report"
		printf "│  %-20s: %s\n" "Host" "$(hostname)"
		printf "│  %-20s: %s\n" "SO" "$os_name"
		printf "│  %-20s: %s\n" "Kernel" "$kernel"
		printf "│  %-20s: %s\n" "Uptime" "$uptime"
		echo "│"
		echo "└──────────────────────────────────────────────────────────────────────────────┘"
		echo ""
		
		# Resumo executivo - DESTAQUE
		echo "┌─ RESUMO EXECUTIVO ───────────────────────────────────────────────────────────┐"
		echo "│"
		
		# Determina ícone de severidade
		case "$GLOBAL_SEVERITY_NAME" in
			OK) icon="✓ " ;;
			INFO) icon="ℹ " ;;
			WARNING) icon="⚠ " ;;
			CRITICAL) icon="✗ " ;;
			*) icon="  " ;;
		esac
		
		printf "│  SEVERIDADE GLOBAL: [%s] %s\n" "$GLOBAL_SEVERITY_NAME" "$icon"
		echo "│"
		echo "└──────────────────────────────────────────────────────────────────────────────┘"
		echo ""
		
		# Tabela de resultados por módulo
		echo "┌─ RESULTADOS POR MÓDULO ──────────────────────────────────────────────────────┐"
		echo "│"
		printf "│  %-15s │ %-15s │ Status\n" "MÓDULO" "SEVERIDADE"
		echo "│  ──────────────┼────────────────┼─────────────"
		
		for module in NETWORK SERVICES SSH USERS; do
			local sev=${MODULE_SEVERITY[$module]:-0}
			local sev_name="OK"
			local status_icon=""
			case "$sev" in
				-1) sev_name="SKIPPED" ; status_icon="-" ;;
				0) sev_name="OK" ; status_icon="✓" ;;
				1) sev_name="INFO" ; status_icon="ℹ" ;;
				2) sev_name="WARNING" ; status_icon="⚠" ;;
				3) sev_name="CRITICAL" ; status_icon="✗" ;;
			esac
			printf "│  %-15s │ %-15s │ %s\n" "$module" "$sev_name" "$status_icon"
		done
		
		echo "│"
		echo "└──────────────────────────────────────────────────────────────────────────────┘"
		echo ""
		
		# Estatísticas de Achados
		echo "┌─ ESTATÍSTICAS DE ACHADOS ────────────────────────────────────────────────────┐"
		echo "│"
		printf "│  %-25s: %3d achados\n" "✗ CRÍTICOS (CRITICAL)" "$count_critical"
		printf "│  %-25s: %3d achados\n" "⚠ AVISOS (WARNING)" "$count_warning"
		printf "│  %-25s: %3d entradas\n" "ℹ INFORMATIVOS (INFO)" "$count_info"
		local total=$((count_critical + count_warning + count_info))
		printf "│  %-25s: %3d total\n" "TOTAL DE ACHADOS" "$total"
		echo "│"
		echo "└──────────────────────────────────────────────────────────────────────────────┘"
		echo ""
		
		# Legenda de severidades
		echo "┌─ LEGENDA DE SEVERIDADES ─────────────────────────────────────────────────────┐"
		echo "│"
		echo "│  ✓  OK       [0] - Nenhum achado significativo"
		echo "│  ℹ  INFO     [1] - Achado informativo, sem impacto imediato"
		echo "│  ⚠  WARNING  [2] - Achado que requer atenção / possível risco"
		echo "│  ✗  CRITICAL [3] - Achado crítico / risco imediato de segurança"
		echo "│"
		echo "└──────────────────────────────────────────────────────────────────────────────┘"
		echo ""
		
		# SEÇÃO DE ACHADOS CRÍTICOS E WARNINGS (DESTAQUE)
		if [ "$count_critical" -gt 0 ] || [ "$count_warning" -gt 0 ]; then
			echo "╔════════════════════════════════════════════════════════════════════════════════╗"
			echo "║                    ⚠  ACHADOS CRÍTICOS E AVISOS  ⚠                            ║"
			echo "║                      (REQUEREM ATENÇÃO IMEDIATA)                             ║"
			echo "╚════════════════════════════════════════════════════════════════════════════════╝"
			echo ""
			
			# Extrair e exibir APENAS achados críticos e warnings
			if [ -f "$LOG_FILE" ]; then
				echo "┌─ CRÍTICOS (CRITICAL) ────────────────────────────────────────────────────────┐"
				echo "│"
				if [ "$count_critical" -gt 0 ]; then
					grep "\[CRITICAL\]" "$LOG_FILE" | while read -r line; do
						echo "│  $line"
					done
				else
					echo "│  Nenhum achado crítico encontrado."
				fi
				echo "│"
				echo "└──────────────────────────────────────────────────────────────────────────────┘"
				echo ""
				
				echo "┌─ AVISOS (WARNING) ───────────────────────────────────────────────────────────┐"
				echo "│"
				if [ "$count_warning" -gt 0 ]; then
					grep "\[WARNING\]" "$LOG_FILE" | while read -r line; do
						echo "│  $line"
					done
				else
					echo "│  Nenhum aviso encontrado."
				fi
				echo "│"
				echo "└──────────────────────────────────────────────────────────────────────────────┘"
				echo ""
			fi
		fi
		
		# Detalhes técnicos por módulo - CONTEÚDO DO LOG ESTRUTURADO
		echo "╔════════════════════════════════════════════════════════════════════════════════╗"
		echo "║                        DETALHES TÉCNICOS POR MÓDULO                           ║"
		echo "╚════════════════════════════════════════════════════════════════════════════════╝"
		echo ""
		
		# Lê o arquivo de log e organiza por seção
		if [ -f "$LOG_FILE" ]; then
			# Extrair e exibir logs do MAIN
			echo "┌─ [0] SEÇÃO PRINCIPAL ─────────────────────────────────────────────────────┐"
			echo "│"
			grep "\[MAIN\]" "$LOG_FILE" | while read -r line; do
				echo "│  $line"
			done
			echo "│"
			echo "└──────────────────────────────────────────────────────────────────────────┘"
			echo ""
			
			# Extrair e exibir logs do NETWORK
			local net_count=$(grep -c "\[NETWORK\]" "$LOG_FILE" || true)
			echo "┌─ [1/4] AUDITORIA DE REDE ($net_count entradas) ─────────────────────────────┐"
			echo "│"
			if grep -q "\[NETWORK\]" "$LOG_FILE"; then
				grep "\[NETWORK\]" "$LOG_FILE" | while read -r line; do
					echo "│  $line"
				done
			else
				echo "│  Nenhuma entrada de auditoria de rede registrada."
			fi
			echo "│"
			echo "└──────────────────────────────────────────────────────────────────────────┘"
			echo ""
			
			# Extrair e exibir logs do SERVICES
			local svc_count=$(grep -c "\[SERVICES\]" "$LOG_FILE" || true)
			echo "┌─ [2/4] AUDITORIA DE SERVIÇOS ($svc_count entradas) ───────────────────────┐"
			echo "│"
			if grep -q "\[SERVICES\]" "$LOG_FILE"; then
				grep "\[SERVICES\]" "$LOG_FILE" | while read -r line; do
					echo "│  $line"
				done
			else
				echo "│  Nenhuma entrada de auditoria de serviços registrada."
			fi
			echo "│"
			echo "└──────────────────────────────────────────────────────────────────────────┘"
			echo ""
			
			# Extrair e exibir logs do SSH
			local ssh_count=$(grep -c "\[SSH\]" "$LOG_FILE" || true)
			echo "┌─ [3/4] AUDITORIA DE ACESSO SSH ($ssh_count entradas) ──────────────────────┐"
			echo "│"
			if grep -q "\[SSH\]" "$LOG_FILE"; then
				grep "\[SSH\]" "$LOG_FILE" | while read -r line; do
					echo "│  $line"
				done
			else
				echo "│  Nenhuma entrada de auditoria de SSH registrada."
			fi
			echo "│"
			echo "└──────────────────────────────────────────────────────────────────────────┘"
			echo ""
			
			# Extrair e exibir logs do USERS
			local usr_count=$(grep -c "\[USERS\]" "$LOG_FILE" || true)
			echo "┌─ [4/4] AUDITORIA DE IDENTIDADE E USUÁRIOS ($usr_count entradas) ──────────┐"
			echo "│"
			if grep -q "\[USERS\]" "$LOG_FILE"; then
				grep "\[USERS\]" "$LOG_FILE" | while read -r line; do
					echo "│  $line"
				done
			else
				echo "│  Nenhuma entrada de auditoria de usuários registrada."
			fi
			echo "│"
			echo "└──────────────────────────────────────────────────────────────────────────┘"
			echo ""
		fi
		
		# Recomendações
		echo "╔════════════════════════════════════════════════════════════════════════════════╗"
		echo "║                           RECOMENDAÇÕES E AÇÕES                               ║"
		echo "╚════════════════════════════════════════════════════════════════════════════════╝"
		echo ""
		
		if [ "$GLOBAL_SEVERITY_NAME" = "CRITICAL" ]; then
			echo "⚠  CRÍTICO - Ação imediata requerida:"
			echo ""
			echo "  • Revise todas as vulnerabilidades críticas encontradas na seção acima"
			echo "  • Implemente correções em caráter de urgência"
			echo "  • Notifique a equipe de segurança responsável"
			echo "  • Documente todas as mudanças realizadas"
			echo "  • Re-execute a auditoria após as correções para validação"
			echo ""
		elif [ "$GLOBAL_SEVERITY_NAME" = "WARNING" ]; then
			echo "⚠  AVISO - Ação recomendada:"
			echo ""
			echo "  • Revise as recomendações de segurança identificadas"
			echo "  • Planeje correções compatíveis com seu calendário"
			echo "  • Implemente melhorias de forma planejada"
			echo "  • Priorize conforme o risco identificado"
			echo "  • Documente justificativas para aceitar riscos residuais (se aplicável)"
			echo ""
		elif [ "$GLOBAL_SEVERITY_NAME" = "OK" ]; then
			echo "✓  SUCESSO - Sistema em conformidade:"
			echo ""
			echo "  • Nenhuma vulnerabilidade crítica detectada"
			echo "  • Continue monitorando o sistema regularmente"
			echo "  • Mantenha as práticas de segurança em vigor"
			echo "  • Realize auditorias periódicas (recomendado: mensalmente)"
			echo "  • Atualize o baseline de configuração esperada conforme mudanças"
			echo ""
		fi
		
		# Rodapé
		echo "╔════════════════════════════════════════════════════════════════════════════════╗"
		echo "║  Relatório Gerado: $timestamp                                              ║"
		echo "║  Arquivo de Log Completo: $(basename "$LOG_FILE")                          ║"
		echo "║  Este relatório é confidencial e deve ser tratado como informação sensível.   ║"
		echo "╚════════════════════════════════════════════════════════════════════════════════╝"
		
	} > "$SUMMARY_FILE"
	
	log_entry "INFO" "MAIN" "Relatório consolidado salvo em: $SUMMARY_FILE"
}

############################################################
# EXIBIÇÃO DE RESUMO NO CONSOLE
############################################################

display_console_summary() {
	echo ""
	echo "│════════════════════════════════════════════════════════════════════════════════│"
	echo "│                     RESUMO FINAL DA AUDITORIA DE SEGURANÇA                    │"
	echo "│════════════════════════════════════════════════════════════════════════════════│"
	echo "│"
	echo "│  Severidade Global: [$GLOBAL_SEVERITY_NAME]"
	echo "│"
	echo "│  Resultados por Módulo:"
	echo "│"
	for module in NETWORK SERVICES SSH USERS; do
		local sev=${MODULE_SEVERITY[$module]:-0}
		local sev_name="OK"
		case "$sev" in
			-1) sev_name="SKIPPED  " ;;
			0) sev_name="OK       " ;;
			1) sev_name="INFO     " ;;
			2) sev_name="WARNING  " ;;
			3) sev_name="CRITICAL " ;;
		esac
		printf "│    %-12s : %s\n" "$module" "$sev_name"
	done
	echo "│"
	echo "│  Arquivos de Saída:"
	echo "│    - Log Principal: $LOG_FILE"
	echo "│    - Relatório Consolidado: $SUMMARY_FILE"
	echo "│"
	echo "│════════════════════════════════════════════════════════════════════════════════│"
	echo ""
}

############################################################
# MAIN EXECUTION
############################################################

main() {
	log_entry "INFO" "MAIN" "Inicializando auditoria de segurança..."
	log_entry "INFO" "MAIN" "Versão: 1.0.0"
	log_entry "INFO" "MAIN" "Host: $(hostname)"
	log_entry "INFO" "MAIN" ""
	
	# Executa módulos selecionados
	if [ "$RUN_NETWORK" -eq 1 ]; then
		run_network_audit || log_entry "WARNING" "MAIN" "Erro ao executar auditoria de rede"
	else
		mark_module_skipped "NETWORK" "network"
	fi

	if [ "$RUN_SERVICES" -eq 1 ]; then
		run_services_audit || log_entry "WARNING" "MAIN" "Erro ao executar auditoria de serviços"
	else
		mark_module_skipped "SERVICES" "services"
	fi

	if [ "$RUN_SSH" -eq 1 ]; then
		run_ssh_audit || log_entry "WARNING" "MAIN" "Erro ao executar auditoria de SSH"
	else
		mark_module_skipped "SSH" "ssh"
	fi

	if [ "$RUN_USERS" -eq 1 ]; then
		run_users_audit || log_entry "WARNING" "MAIN" "Erro ao executar auditoria de usuários"
	else
		mark_module_skipped "USERS" "users"
	fi
	
	# Registra conclusão ANTES de gerar o relatório
	log_entry "INFO" "MAIN" "Auditoria concluída com severidade global: $GLOBAL_SEVERITY_NAME"
	
	# Gera relatório (agora com todas as entradas inclusas)
	generate_summary_report
	
	# Exibe resumo no console
	display_console_summary
	
	# Retorna código apropriado
	return "$GLOBAL_SEVERITY"
}

# Executa se não estiver sendo sourced
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	parse_args "$@"
	setup_environment
	main
	exit_code=$?
	exit "$exit_code"
fi
