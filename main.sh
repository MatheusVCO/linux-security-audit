
#!/bin/bash

# Inclui funções utilitárias comuns para compatibilidade
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

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
############################################################

set -euo pipefail

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

run_network_audit() {
	log_entry "INFO" "MAIN" "========== INICIANDO AUDITORIA DE REDE =========="
	
	local network_script="${SCRIPT_DIR}/checks/network.sh"
	
	if [ ! -f "$network_script" ]; then
		log_entry "WARNING" "MAIN" "Arquivo não encontrado: $network_script"
		return 1
	fi
	
	# Executa e captura saída
	local network_output
	local network_exit=0
	network_output=$(bash "$network_script" 2>&1) || network_exit=$?
	
	# Armazena logs do módulo
	MODULE_LOGS["network"]="$network_output"
	
	# Processa saída para extrair severidade
	local detected_severity="OK"
	if echo "$network_output" | grep -q "\[CRITICAL\]"; then
		detected_severity="CRITICAL"
	elif echo "$network_output" | grep -q "\[WARNING\]"; then
		detected_severity="WARNING"
	elif echo "$network_output" | grep -q "\[INFO\]"; then
		detected_severity="INFO"
	fi
	
	# Log estruturado da auditoria de rede
	while IFS= read -r line; do
		if [[ "$line" =~ \[(OK|INFO|WARNING|CRITICAL)\] ]]; then
			# Extrai severidade da linha original
			local line_sev=$(echo "$line" | grep -oP '(?<=\[)[A-Z]+(?=\])')
			echo "$line" >> "$LOG_FILE"
		fi
	done <<< "$network_output"
	
	update_global_severity "NETWORK" "$detected_severity"
	log_entry "$detected_severity" "MAIN" "Auditoria de REDE concluída com severidade: $detected_severity"
	log_entry "INFO" "MAIN" ""
}

############################################################
# MÓDULO: SERVICES AUDIT
############################################################

run_services_audit() {
	log_entry "INFO" "MAIN" "========== INICIANDO AUDITORIA DE SERVIÇOS =========="
	
	local services_script="${SCRIPT_DIR}/checks/services.sh"
	
	if [ ! -f "$services_script" ]; then
		log_entry "WARNING" "MAIN" "Arquivo não encontrado: $services_script"
		return 1
	fi
	
	# Executa e captura saída
	local services_output
	local services_exit=0
	services_output=$(bash "$services_script" 2>&1) || services_exit=$?
	
	# Armazena logs do módulo
	MODULE_LOGS["services"]="$services_output"
	
	# Processa saída para extrair severidade
	local detected_severity="OK"
	if echo "$services_output" | grep -q "\[CRITICAL\]"; then
		detected_severity="CRITICAL"
	elif echo "$services_output" | grep -q "\[WARNING\]"; then
		detected_severity="WARNING"
	elif echo "$services_output" | grep -q "\[INFO\]"; then
		detected_severity="INFO"
	fi
	
	# Log estruturado da auditoria de serviços
	while IFS= read -r line; do
		if [[ "$line" =~ \[(OK|INFO|WARNING|CRITICAL)\] ]]; then
			echo "$line" >> "$LOG_FILE"
		fi
	done <<< "$services_output"
	
	update_global_severity "SERVICES" "$detected_severity"
	log_entry "$detected_severity" "MAIN" "Auditoria de SERVIÇOS concluída com severidade: $detected_severity"
	log_entry "INFO" "MAIN" ""
}

############################################################
# MÓDULO: SSH AUDIT
############################################################

run_ssh_audit() {
	log_entry "INFO" "MAIN" "========== INICIANDO AUDITORIA DE SSH =========="
	
	local ssh_script="${SCRIPT_DIR}/checks/ssh.sh"
	
	if [ ! -f "$ssh_script" ]; then
		log_entry "WARNING" "MAIN" "Arquivo não encontrado: $ssh_script"
		return 1
	fi
	
	# Executa e captura saída
	local ssh_output
	local ssh_exit=0
	ssh_output=$(bash "$ssh_script" 2>&1) || ssh_exit=$?
	
	# Armazena logs do módulo
	MODULE_LOGS["ssh"]="$ssh_output"
	
	# Processa saída para extrair severidade
	local detected_severity="OK"
	if echo "$ssh_output" | grep -q "CRITICAL"; then
		detected_severity="CRITICAL"
	elif echo "$ssh_output" | grep -q "WARNING"; then
		detected_severity="WARNING"
	elif echo "$ssh_output" | grep -q "INFO"; then
		detected_severity="INFO"
	fi
	
	# Log estruturado da auditoria de SSH
	while IFS= read -r line; do
		echo "$(date '+%Y-%m-%d %H:%M:%S') [${line%%:*}] [SSH] ${line}" >> "$LOG_FILE"
	done <<< "$ssh_output"
	
	update_global_severity "SSH" "$detected_severity"
	log_entry "$detected_severity" "MAIN" "Auditoria de SSH concluída com severidade: $detected_severity"
	log_entry "INFO" "MAIN" ""
}

############################################################
# MÓDULO: USERS AUDIT
############################################################

run_users_audit() {
	log_entry "INFO" "MAIN" "========== INICIANDO AUDITORIA DE USUÁRIOS =========="
	
	local users_script="${SCRIPT_DIR}/checks/users.sh"
	local baseline_file="${SCRIPT_DIR}/admins.baseline"
	local users_args=()
	
	if [ ! -f "$users_script" ]; then
		log_entry "WARNING" "MAIN" "Arquivo não encontrado: $users_script"
		return 1
	fi

	if [ -r "$baseline_file" ]; then
		users_args+=("-b" "$baseline_file")
		log_entry "INFO" "MAIN" "Usando baseline de administradores: $baseline_file"
	fi
	
	# Executa e captura saída
	local users_output
	local users_exit=0
	users_output=$(bash "$users_script" "${users_args[@]}" 2>&1) || users_exit=$?
	
	# Armazena logs do módulo
	MODULE_LOGS["users"]="$users_output"
	
	# Processa saída para extrair severidade
	local detected_severity="OK"
	if echo "$users_output" | grep -q "CRITICAL"; then
		detected_severity="CRITICAL"
	elif echo "$users_output" | grep -q "WARNING"; then
		detected_severity="WARNING"
	elif echo "$users_output" | grep -q "INFO"; then
		detected_severity="INFO"
	fi
	
	# Log estruturado da auditoria de usuários
	while IFS= read -r line; do
		echo "$(date '+%Y-%m-%d %H:%M:%S') [USERS] $line" >> "$LOG_FILE"
	done <<< "$users_output"
	
	update_global_severity "USERS" "$detected_severity"
	log_entry "$detected_severity" "MAIN" "Auditoria de USUÁRIOS concluída com severidade: $detected_severity"
	log_entry "INFO" "MAIN" ""
}

############################################################
# GERAÇÃO DE RELATÓRIO CONSOLIDADO
############################################################

generate_summary_report() {
	log_entry "INFO" "MAIN" "========== GERANDO RELATÓRIO CONSOLIDADO =========="
	
	{
		echo "================================================================================"
		echo "RELATÓRIO CONSOLIDADO DE AUDITORIA DE SEGURANÇA LINUX"
		echo "================================================================================"
		echo ""
		echo "Data/Hora: $(date '+%d/%m/%Y %H:%M:%S')"
		echo "Host: $(hostname)"
		echo "SO: $(uname -s) $(uname -r)"
		echo ""
		echo "================================================================================"
		echo "RESUMO EXECUTIVO"
		echo "================================================================================"
		echo ""
		echo "Severidade Global: $GLOBAL_SEVERITY_NAME"
		echo ""
		
		# Detalhes por módulo
		echo "Severidade por Módulo:"
		echo ""
		for module in NETWORK SERVICES SSH USERS; do
			local module_lower=$(echo "$module" | tr '[:upper:]' '[:lower:]')
			local sev=${MODULE_SEVERITY[$module]:-0}
			local sev_name="OK"
			case "$sev" in
				0) sev_name="OK" ;;
				1) sev_name="INFO" ;;
				2) sev_name="WARNING" ;;
				3) sev_name="CRITICAL" ;;
			esac
			printf "  %-12s : %s\n" "$module" "$sev_name"
		done
		
		echo ""
		echo "================================================================================"
		echo "LOGS COMPLETOS POR SEÇÃO"
		echo "================================================================================"
		echo ""
		
		# Logs de REDE
		if [ -n "${MODULE_LOGS[network]:-}" ]; then
			echo "--- SEÇÃO: NETWORK (AUDITORIA DE REDE) ---"
			echo "${MODULE_LOGS[network]}"
			echo ""
		fi
		
		# Logs de SERVIÇOS
		if [ -n "${MODULE_LOGS[services]:-}" ]; then
			echo "--- SEÇÃO: SERVICES (AUDITORIA DE SERVIÇOS) ---"
			echo "${MODULE_LOGS[services]}"
			echo ""
		fi
		
		# Logs de SSH
		if [ -n "${MODULE_LOGS[ssh]:-}" ]; then
			echo "--- SEÇÃO: SSH (AUDITORIA DE ACESSO SSH) ---"
			echo "${MODULE_LOGS[ssh]}"
			echo ""
		fi
		
		# Logs de USUÁRIOS
		if [ -n "${MODULE_LOGS[users]:-}" ]; then
			echo "--- SEÇÃO: USERS (AUDITORIA DE IDENTIDADE) ---"
			echo "${MODULE_LOGS[users]}"
			echo ""
		fi
		
		echo "================================================================================"
		echo "INTERPRETAÇÃO DE SEVERIDADES"
		echo "================================================================================"
		echo ""
		echo "  OK       (0) - Nenhum achado significativo"
		echo "  INFO     (1) - Achado informativo, sem impacto imediato"
		echo "  WARNING  (2) - Achado que requer atenção / possível risco"
		echo "  CRITICAL (3) - Achado crítico / risco imediato de segurança"
		echo ""
		echo "================================================================================"
		echo "FIM DO RELATÓRIO"
		echo "================================================================================"
		
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
		local module_lower=$(echo "$module" | tr '[:upper:]' '[:lower:]')
		local sev=${MODULE_SEVERITY[$module]:-0}
		local sev_name="OK"
		case "$sev" in
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
	
	# Executa todos os módulos
	run_network_audit || log_entry "WARNING" "MAIN" "Erro ao executar auditoria de rede"
	run_services_audit || log_entry "WARNING" "MAIN" "Erro ao executar auditoria de serviços"
	run_ssh_audit || log_entry "WARNING" "MAIN" "Erro ao executar auditoria de SSH"
	run_users_audit || log_entry "WARNING" "MAIN" "Erro ao executar auditoria de usuários"
	
	# Gera relatório
	generate_summary_report
	
	# Exibe resumo no console
	display_console_summary
	
	log_entry "INFO" "MAIN" "Auditoria concluída com severidade global: $GLOBAL_SEVERITY_NAME"
	
	# Retorna código apropriado
	return "$GLOBAL_SEVERITY"
}

# Executa se não estiver sendo sourced
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	setup_environment
	main
	exit_code=$?
	exit "$exit_code"
fi
