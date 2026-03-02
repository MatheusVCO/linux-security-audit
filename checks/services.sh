#!/bin/bash

# Inclui funções utilitárias comuns para compatibilidade
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
#!/bin/bash

############################################################
# MÓDULO: SERVICES AUDIT
#
# Objetivo:
# Avaliar serviços ativos no sistema, verificando
# aderência ao princípio de menor superfície de ataque.
	if ! command_exists systemctl; then
		svc_log WARNING "systemctl não disponível. Não é possível listar serviços ativos."
		set_max_severity WARNING
		return
	fi
	mapfile -t active_services < <(systemctl list-units --type=service --state=active --no-pager --plain 2>/dev/null | grep -v "^UNIT " | grep -v "^[0-9].*loaded" | awk '{print $1}' | grep -v "^$" | sed 's/\.service$//')
# Risco Mitigado:
# - Serviços desnecessários em execução
# - Serviços habilitados para iniciar automaticamente
# - Serviços sensíveis ativos sem necessidade
# - Ampliação indevida da superfície de ataque
#
# Escopo:
# Este módulo analisa:
# - Serviços ativos no momento
	if ! command_exists systemctl; then
		svc_log WARNING "systemctl não disponível. Não é possível listar serviços habilitados."
		set_max_severity WARNING
		return
	fi
	mapfile -t enabled_services < <(systemctl list-unit-files --type=service --state=enabled --no-pager --plain 2>/dev/null | grep -v "^FILE" | grep -v "^[0-9].*unit files" | awk '{print $1}' | sed 's/\.service$//' | grep -v "^$")
# - Serviços potencialmente sensíveis
#
# Observação:
# Este módulo NÃO deve imprimir diretamente.
# Toda saída deve utilizar a função de log central definida no main.
	if ! command_exists systemctl; then
		svc_log WARNING "systemctl não disponível. Não é possível listar serviços ativos."
		set_max_severity WARNING
		return
	fi
	mapfile -t active_services < <(systemctl list-units --type=service --state=active --no-pager --plain 2>/dev/null | grep -v "^UNIT " | grep -v "^[0-9].*loaded" | awk '{print $1}' | sed 's/\.service$//' | grep -v "^$")

SCRIPT_NAME="services"

# Baseline de serviços esperados (pode ser carregado de arquivo em evolução futura)
EXPECTED_ACTIVE_SERVICES=("systemd-journald" "systemd-logind" "systemd-udevd")
SENSITIVE_SERVICES=("apache2" "nginx" "mysql" "postgresql" "mongodb" "redis" "openssh-server" "sshd" "docker" "docker.service" "smbd" "nfs-server")
CRITICAL_SERVICES=("apache2" "nginx" "mysql" "postgresql" "sshd" "openssh-server" "docker" "docker.service")

############################################################
# HELPERS: usa o log central se disponível (wrapper seguro)
############################################################

svc_log() {
	# Usage: svc_log SEVERITY message...
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
		if echo "$def" | grep -q "svc_log"; then
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
	if ! command_exists systemctl; then
		svc_log WARNING "systemctl não disponível. Não é possível listar serviços em estado failed."
		set_max_severity WARNING
		return
	fi
	mapfile -t failed_services < <(systemctl list-units --type=service --state=failed --no-pager --plain 2>/dev/null | grep -v "^UNIT " | grep -v "^[0-9].*loaded" | awk '{print $1}' | sed 's/\.service$//' | grep -v "^$")
	case "$sev_name" in
		OK) sev=0 ;; INFO) sev=1 ;; WARNING) sev=2 ;; CRITICAL) sev=3 ;; *) sev=0 ;;
	esac
	if [ -z "${SERVICES_MAX_SEVERITY+x}" ] || [ "$sev" -gt "$SERVICES_MAX_SEVERITY" ]; then
		SERVICES_MAX_SEVERITY=$sev
		SERVICES_MAX_SEVERITY_NAME=$sev_name
	fi
}

report_exit_code() {
	case "$SERVICES_MAX_SEVERITY" in
	if ! command_exists systemctl; then
		svc_log WARNING "systemctl não disponível. Não é possível verificar serviços masked."
		set_max_severity WARNING
		return
	fi
	local dangerous_services=("telnet" "rsh" "rlogin" "nis")
		1) return 0 ;;
		2) return 1 ;;
		3) return 2 ;;
		*) return 0 ;;
	esac
}

is_sensitive_service() {
	local service="$1"
	for sensitive in "${SENSITIVE_SERVICES[@]}"; do
		if [[ "$service" == *"$sensitive"* ]]; then
			return 0
		fi
	done
	return 1
}

is_critical_service() {
	local service="$1"
	for critical in "${CRITICAL_SERVICES[@]}"; do
		if [[ "$service" == *"$critical"* ]]; then
			return 0
		fi
	done
	return 1
}

############################################################
# CONTROLE 1 — SERVIÇOS ATIVOS
#
# Pergunta:
# Quais serviços estão atualmente ativos no sistema?
#
# Risco:
# Cada serviço ativo representa código rodando com privilégios.
# Código rodando = possível vetor de exploração.
#
# Estratégia:
# - Identificar serviços em estado "active"
# - Classificar serviços críticos vs comuns
#
# Critério Esperado:
# Apenas serviços previstos no baseline devem estar ativos.
#
# Severidade:
# - WARNING se serviço inesperado estiver ativo
# - CRITICAL se serviço sensível inesperado estiver ativo
# - OK se estado estiver conforme baseline
############################################################

check_active_services() {
	svc_log INFO "${SCRIPT_NAME^^}: Verificando serviços ativos..."

	# Get list of active services
	mapfile -t active_services < <(systemctl list-units --type=service --state=active --no-pager --plain 2>/dev/null | grep -v "^UNIT " | grep -v "^[0-9].*loaded" | awk '{print $1}' | grep -v "^$" | sed 's/\.service$//')

	if [ ${#active_services[@]} -eq 0 ]; then
		svc_log WARNING "${SCRIPT_NAME^^}: Não foi possível obter lista de serviços ativos"
		set_max_severity WARNING
		return
	fi

	svc_log INFO "${SCRIPT_NAME^^}: Encontrados ${#active_services[@]} serviços ativos"
	
	for service in "${active_services[@]}"; do
		# skip common system services
		if [[ "$service" =~ ^(systemd|user@|dbus|getty) ]]; then
			svc_log INFO "${SCRIPT_NAME^^}: Serviço do sistema ativo: $service"
			continue
		fi

		# check if service is in expected baseline
		found_in_baseline=0
		for expected in "${EXPECTED_ACTIVE_SERVICES[@]}"; do
			if [[ "$service" == "$expected" ]]; then
				found_in_baseline=1
				break
			fi
		done

		if [ $found_in_baseline -eq 1 ]; then
			svc_log INFO "${SCRIPT_NAME^^}: Serviço esperado ativo: $service"
		else
			# Check if it's a critical/sensitive service running unexpectedly
			if is_critical_service "$service"; then
				svc_log CRITICAL "${SCRIPT_NAME^^}: Serviço CRÍTICO inesperadamente ativo: $service"
				set_max_severity CRITICAL
			elif is_sensitive_service "$service"; then
				svc_log WARNING "${SCRIPT_NAME^^}: Serviço sensível ativo (revisar necessidade): $service"
				set_max_severity WARNING
			else
				svc_log INFO "${SCRIPT_NAME^^}: Serviço ativo não baseline: $service"
			fi
		fi
	done

	[ ${#active_services[@]} -gt 0 ] && set_max_severity OK
}

############################################################
# CONTROLE 2 — SERVIÇOS HABILITADOS NO BOOT
#
# Pergunta:
# Quais serviços estão configurados para iniciar automaticamente?
#
# Risco:
# Serviços habilitados no boot podem permanecer ativos
# mesmo que não estejam sendo utilizados.
#
# Estratégia:
# - Identificar serviços com status "enabled"
#
# Critério Esperado:
# Apenas serviços essenciais devem iniciar automaticamente.
#
# Severidade:
# - WARNING se serviço desnecessário estiver habilitado
# - OK se apenas serviços esperados estiverem habilitados
############################################################

check_enabled_services() {
	svc_log INFO "${SCRIPT_NAME^^}: Verificando serviços habilitados no boot..."

	# Get list of enabled services
	mapfile -t enabled_services < <(systemctl list-unit-files --type=service --state=enabled --no-pager --plain 2>/dev/null | grep -v "^FILE" | grep -v "^[0-9].*unit files" | awk '{print $1}' | sed 's/\.service$//' | grep -v "^$")

	if [ ${#enabled_services[@]} -eq 0 ]; then
		svc_log INFO "${SCRIPT_NAME^^}: Nenhum serviço habilitado encontrado (status: may-offline)"
		set_max_severity OK
		return
	fi

	svc_log INFO "${SCRIPT_NAME^^}: Encontrados ${#enabled_services[@]} serviços habilitados no boot"

	for service in "${enabled_services[@]}"; do
		# Skip common system services
		if [[ "$service" =~ ^(systemd|user@|getty) ]]; then
			svc_log INFO "${SCRIPT_NAME^^}: Serviço do sistema habilitado: $service"
			continue
		fi

		# Check against baseline
		found_in_baseline=0
		for expected in "${EXPECTED_ACTIVE_SERVICES[@]}"; do
			if [[ "$service" == "$expected" ]]; then
				found_in_baseline=1
				break
			fi
		done

		if [ $found_in_baseline -eq 1 ]; then
			svc_log INFO "${SCRIPT_NAME^^}: Serviço esperado habilitado: $service"
		else
			if is_sensitive_service "$service"; then
				svc_log WARNING "${SCRIPT_NAME^^}: Serviço sensível habilitado no boot (revisar necessidade): $service"
				set_max_severity WARNING
			else
				svc_log INFO "${SCRIPT_NAME^^}: Serviço não-baseline habilitado: $service"
			fi
		fi
	done

	[ ${#enabled_services[@]} -gt 0 ] && set_max_severity OK
}

############################################################
# CONTROLE 3 — SERVIÇOS SENSÍVEIS
#
# Exemplos:
# - Servidores web
# - Bancos de dados
# - Serviços de compartilhamento
# - Serviços administrativos remotos
#
# Pergunta:
# Existem serviços sensíveis ativos que ampliam risco?
#
# Risco:
# Serviços críticos expostos ou mal configurados
# aumentam probabilidade de exploração.
#
# Critério:
# Detectar presença de serviços classificados como críticos
# e validar se sua execução é esperada.
#
# Severidade:
# - CRITICAL se serviço sensível estiver ativo fora do baseline
# - WARNING se ativo mas requer revisão
############################################################

check_sensitive_services() {
	svc_log INFO "${SCRIPT_NAME^^}: Verificando presença de serviços sensíveis..."

	# Get list of all active services
	mapfile -t active_services < <(systemctl list-units --type=service --state=active --no-pager --plain 2>/dev/null | grep -v "^UNIT " | grep -v "^[0-9].*loaded" | awk '{print $1}' | sed 's/\.service$//' | grep -v "^$")

	local sensitive_count=0
	local critical_count=0

	for service in "${active_services[@]}"; do
		if is_critical_service "$service"; then
			# Check if it's expected
			found_expected=0
			# You could add specific expected critical services here
			if [ $found_expected -eq 0 ]; then
				svc_log CRITICAL "${SCRIPT_NAME^^}: Serviço CRÍTICO ativo sem estar no baseline: $service"
				set_max_severity CRITICAL
				((critical_count++))
			fi
		elif is_sensitive_service "$service"; then
			svc_log WARNING "${SCRIPT_NAME^^}: Serviço sensível ativo: $service (valide se necessário)"
			set_max_severity WARNING
			((sensitive_count++))
		fi
	done

	if [ $critical_count -gt 0 ]; then
		svc_log INFO "${SCRIPT_NAME^^}: $critical_count serviço(s) crítico(s) ativo(s)"
	fi

	if [ $sensitive_count -gt 0 ]; then
		svc_log INFO "${SCRIPT_NAME^^}: $sensitive_count serviço(s) sensível(is) ativo(s)"
	fi

	if [ $critical_count -eq 0 ] && [ $sensitive_count -eq 0 ]; then
		svc_log OK "${SCRIPT_NAME^^}: Nenhum serviço sensível/crítico ativo fora do esperado"
		set_max_severity OK
	fi
}

############################################################
# CONTROLE 4 — SERVIÇOS FALHANDO OU INSTÁVEIS
#
# Pergunta:
# Existem serviços em estado failed ou em restart contínuo?
#
# Risco:
# Serviço falhando pode indicar:
# - Configuração incorreta
# - Tentativa de exploração
# - Problema operacional
#
# Critério:
# Identificar serviços com status "failed"
#
# Severidade:
# - WARNING para falha isolada
# - CRITICAL se serviço crítico estiver falhando
############################################################

check_failed_services() {
	svc_log INFO "${SCRIPT_NAME^^}: Verificando serviços em estado failed..."

	# Get list of failed services
	mapfile -t failed_services < <(systemctl list-units --type=service --state=failed --no-pager --plain 2>/dev/null | grep -v "^UNIT " | grep -v "^[0-9].*loaded" | awk '{print $1}' | sed 's/\.service$//' | grep -v "^$")

	if [ ${#failed_services[@]} -eq 0 ]; then
		svc_log OK "${SCRIPT_NAME^^}: Nenhum serviço em estado failed"
		set_max_severity OK
		return
	fi

	svc_log WARNING "${SCRIPT_NAME^^}: ${#failed_services[@]} serviço(s) em estado failed"

	for service in "${failed_services[@]}"; do
		svc_log INFO "${SCRIPT_NAME^^}: Serviço falhando: $service"

		if is_critical_service "$service"; then
			svc_log CRITICAL "${SCRIPT_NAME^^}: Serviço CRÍTICO falhando: $service"
			set_max_severity CRITICAL
		else
			svc_log WARNING "${SCRIPT_NAME^^}: Serviço falhando: $service"
			set_max_severity WARNING
		fi

		# Get failure reason if available
		reason=$(systemctl status "$service" 2>/dev/null | grep -i "failed" | head -1 || true)
		if [ -n "$reason" ]; then
			svc_log INFO "${SCRIPT_NAME^^}: Motivo: $reason"
		fi
	done
}

############################################################
# CONTROLE 5 — MASK de serviços perigosos
#
# Estratégia complementar:
# Detectar se serviços perigosos estão "masked"
# (desabilitados permanentemente pelo sistema)
#
# Observação:
# Este é um controle de segurança defensiva que verifica
# se serviços potencialmente perigosos estão bloqueados.
############################################################

check_masked_services() {
	svc_log INFO "${SCRIPT_NAME^^}: Verificando serviços em estado 'masked'..."

	# Serviços que idealmente deveriam estar masked
	local dangerous_services=("telnet" "rsh" "rlogin" "nis")

	for service in "${dangerous_services[@]}"; do
		state=$(systemctl is-enabled "$service" 2>/dev/null || echo "not-found")
		case "$state" in
			masked)
				svc_log OK "${SCRIPT_NAME^^}: Serviço perigoso corretamente masked: $service"
				set_max_severity OK
				;;
			enabled|disabled|indirect|static|generated)
				if [ "$state" != "not-found" ]; then
					svc_log WARNING "${SCRIPT_NAME^^}: Serviço perigoso NÃO está masked: $service (estado: $state)"
					set_max_severity WARNING
				fi
				;;
		esac
	done
}

############################################################
# SAÍDA DO MÓDULO
#
# O módulo deve:
# - Registrar eventos via função central de log
# - Atualizar severidade máxima encontrada
# - Retornar código compatível com severidade
#
# O main.sh será responsável por:
# - Consolidar resultados
# - Gerar resumo final
# - Definir exit code global
############################################################

# Main execution
main_services_audit() {
	svc_log INFO "${SCRIPT_NAME^^}: Iniciando auditoria de serviços..."

	# Initialize severity
	SERVICES_MAX_SEVERITY=0
	SERVICES_MAX_SEVERITY_NAME="OK"

	# Run all checks
	check_active_services
	check_enabled_services
	check_sensitive_services
	check_failed_services
	check_masked_services

	# Log summary
	svc_log INFO "${SCRIPT_NAME^^}: Auditoria completa. Severidade máxima: ${SERVICES_MAX_SEVERITY_NAME}"

	# Return appropriate exit code
	report_exit_code
}

# Execute main if script is executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
	main_services_audit
fi
