#!/bin/bash

# Common utility functions for cross-platform compatibility in Linux

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