#!/bin/bash
# AWS NIST 800-53 / 800-171 Compliance Check Wrapper
# - Reads mgmt_role_* and AWS creds from ~/.aws/config
# - Optionally pre-assumes a member-account role before running Python
# - Creates venv, installs deps, runs src/main.py

set -euo pipefail

# ────────────────────────────────────────────────────────────────────────────────
# Colors
# ────────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_message() {
  local color="$1"; shift
  echo -e "${color}$*${NC}"
}

usage() {
  cat << 'EOF'
Usage: run_compliance_checks.sh [OPTIONS]

AWS NIST Compliance Checker (800-53 and 800-171)

OPTIONS:
  -k, --access-key KEY         AWS Access Key ID
  -s, --secret-key KEY         AWS Secret Access Key
  -t, --session-token TOKEN    AWS Session Token
  -r, --region REGION          AWS Region (default: us-west-2)
  -g, --git-repo URL           Git repository URL for security checks
  -b, --git-branch BRANCH      Git branch to use (default: main)
  -o, --output-dir DIR         Output directory for reports (default: ./reports)
  -c, --checks LIST            Comma-separated list of check IDs to run
  -x, --skip-checks LIST       Comma-separated list of check IDs to skip
  -l, --severity LEVEL         Minimum severity (LOW, MEDIUM, HIGH, CRITICAL)
  -f, --format FORMAT          Report format (all, csv, nist-53, nist-171, multi-framework, json)
  -w, --framework FRAMEWORK    (Deprecated; use --format)
  -p, --parallel               Enable parallel execution (default: true)
      --workers NUM            Number of parallel workers (default: 20)
      --pre-assume-role-arn ARN          Member-account role to assume before running Python
      --pre-assume-session-name NAME     Session name for pre-assume (default: precheck-session)
      --pre-assume-duration SECONDS      Duration for pre-assume (default: 3600)
  -h, --help                   Show this help

CREDENTIAL SOURCES (precedence):
  1) CLI flags (-k/-s/-t)
  2) Existing environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
  3) ~/.aws/config under the active profile (AWS_PROFILE/AWS_DEFAULT_PROFILE or [default])

MGMT ROLE SETTINGS (read from ~/.aws/config under active profile):
  mgmt_role_arn                (required for the segregation check)
  mgmt_role_region             (default: us-east-1)
  mgmt_role_duration           (default: 900)
  mgmt_role_session_name       (default: segregation-check)

OPTIONAL CONFIG KEYS:
  pre_assume_role_arn          (default member role to assume before running Python)

Examples:
  AWS_PROFILE=default ./run_compliance_checks.sh --pre-assume-role-arn arn:aws:iam::314146328961:role/KovrAuditRole
  ./run_compliance_checks.sh -k KEY -s SECRET -t TOKEN -r us-east-1
EOF
}

# ────────────────────────────────────────────────────────────────────────────────
# Defaults
# ────────────────────────────────────────────────────────────────────────────────
GIT_REPO=""
GIT_BRANCH="main"
OUTPUT_DIR="./reports"
AWS_REGION="us-west-2"
VENV_DIR=".venv"

CHECKS=""
SKIP_CHECKS=""
SEVERITY=""
FORMAT="all"
FRAMEWORK="both"
PARALLEL="--parallel"
WORKERS="20"

PRE_ASSUME_ROLE_ARN=""
PRE_ASSUME_SESSION_NAME="precheck-session"
PRE_ASSUME_DURATION="3600"

# ────────────────────────────────────────────────────────────────────────────────
# Parse Args
# ────────────────────────────────────────────────────────────────────────────────
TEMP=$(getopt -o k:s:t:r:g:b:o:c:x:l:f:w:ph \
  --long access-key:,secret-key:,session-token:,region:,git-repo:,git-branch:,output-dir:,checks:,skip-checks:,severity:,format:,framework:,parallel,workers:,help,pre-assume-role-arn:,pre-assume-session-name:,pre-assume-duration: \
  -n "$0" -- "$@")
eval set -- "$TEMP"

ACCESS_KEY=""
SECRET_KEY=""
SESSION_TOKEN=""
REGION_PROVIDED=false

while true; do
  case "$1" in
    -k|--access-key)        ACCESS_KEY="$2"; shift 2 ;;
    -s|--secret-key)        SECRET_KEY="$2"; shift 2 ;;
    -t|--session-token)     SESSION_TOKEN="$2"; shift 2 ;;
    -r|--region)            AWS_REGION="$2"; REGION_PROVIDED=true; shift 2 ;;
    -g|--git-repo)          GIT_REPO="$2"; shift 2 ;;
    -b|--git-branch)        GIT_BRANCH="$2"; shift 2 ;;
    -o|--output-dir)        OUTPUT_DIR="$2"; shift 2 ;;
    -c|--checks)            CHECKS="$2"; shift 2 ;;
    -x|--skip-checks)       SKIP_CHECKS="$2"; shift 2 ;;
    -l|--severity)          SEVERITY="$2"; shift 2 ;;
    -f|--format)            FORMAT="$2"; shift 2 ;;
    -w|--framework)         FRAMEWORK="$2"; shift 2 ;;
    -p|--parallel)          PARALLEL="--parallel"; shift ;;
        --workers)          WORKERS="$2"; shift 2 ;;
        --pre-assume-role-arn)     PRE_ASSUME_ROLE_ARN="$2"; shift 2 ;;
        --pre-assume-session-name) PRE_ASSUME_SESSION_NAME="$2"; shift 2 ;;
        --pre-assume-duration)     PRE_ASSUME_DURATION="$2"; shift 2 ;;
    -h|--help)              usage; exit 0 ;;
    --) shift; break ;;
    *) echo "Internal error!"; exit 1 ;;
  esac
done

# ────────────────────────────────────────────────────────────────────────────────
# Header
# ────────────────────────────────────────────────────────────────────────────────
print_message "$BLUE" "
╔═══════════════════════════════════════════════════════════╗
║             AWS NIST Compliance Checker                   ║
║            Supporting 800-53 and 800-171                  ║
║                 Bash Wrapper v1.2.0                       ║
╚═══════════════════════════════════════════════════════════╝
"

print_message "$YELLOW" "Checking dependencies..."
command -v python3 >/dev/null 2>&1 || { print_message "$RED" "Python 3 is required."; exit 1; }
if [ -n "$GIT_REPO" ]; then
  command -v git >/dev/null 2>&1 || { print_message "$RED" "Git is required for --git-repo."; exit 1; }
fi

# ────────────────────────────────────────────────────────────────────────────────
# Config Helpers
# ────────────────────────────────────────────────────────────────────────────────
ACTIVE_PROFILE="${AWS_PROFILE:-${AWS_DEFAULT_PROFILE:-default}}"
AWS_CONFIG_FILE_DEFAULT="$HOME/.aws/config"

aws_cfg_get() {
  # $1 = key
  local key="$1"
  local profile="$ACTIVE_PROFILE"
  local cfg_file="${AWS_CONFIG_FILE:-$AWS_CONFIG_FILE_DEFAULT}"

  if command -v aws >/dev/null 2>&1; then
    if [[ "$profile" == "default" ]]; then
      aws configure get "$key" 2>/dev/null || true
    else
      aws configure get "profile.${profile}.${key}" 2>/dev/null || true
    fi
    return
  fi

  # Manual parse as fallback
  awk -v prof="$profile" -v key="$key" '
    BEGIN{ in_section=0; want=(prof=="default"?"default":"profile " prof); }
    /^\s*\[/ { in_section=0; sec=$0; gsub(/^\s*\[|\]\s*$/,"",sec); if (sec==want) in_section=1; next }
    in_section && $0 ~ "^[[:space:]]*"key"[[:space:]]*=" {
      val=$0; sub(/^[[:space:]]*[^=]+=/,"",val); gsub(/^[[:space:]]+|[[:space:]]+$/,"",val); print val; exit
    }
  ' "$cfg_file" 2>/dev/null || true
}

trim() { awk '{$1=$1;print}'; }

# Prompt user for input with default from config
prompt_with_default() {
  local prompt_text="$1"
  local config_key="$2"
  local default_value="$3"
  local var_name="$4"
  
  # Get value from config if not already set
  if [[ -z "${!var_name:-}" ]]; then
    local config_value
    config_value="$(aws_cfg_get "$config_key" || true)"
    if [[ -n "$config_value" ]]; then
      default_value="$config_value"
    fi
  else
    # Use existing value as default
    default_value="${!var_name}"
  fi
  
  # Show prompt with default
  local user_input
  if [[ -n "$default_value" ]]; then
    read -p "${prompt_text} [Default: ${default_value}]: " user_input
  else
    read -p "${prompt_text}: " user_input
  fi
  
  # Use default if empty
  if [[ -z "$user_input" ]]; then
    user_input="$default_value"
  fi
  
  # Return the value
  echo "$user_input"
}

# Load mgmt role + creds from ~/.aws/config (without clobbering pre-set env/flags)
load_mgmt_role_and_creds_from_config() {
  # mgmt role vars (always export; Python reads them; empty is OK)
  : "${mgmt_role_arn:=$(aws_cfg_get mgmt_role_arn || true)}"
  : "${mgmt_role_region:=$(aws_cfg_get mgmt_role_region || true)}"
  : "${mgmt_role_duration:=$(aws_cfg_get mgmt_role_duration || true)}"
  : "${mgmt_role_session_name:=$(aws_cfg_get mgmt_role_session_name || true)}"

  [[ -z "${mgmt_role_region:-}" ]] && mgmt_role_region="us-east-1"
  [[ -z "${mgmt_role_duration:-}" ]] && mgmt_role_duration="900"
  [[ -z "${mgmt_role_session_name:-}" ]] && mgmt_role_session_name="segregation-check"

  export mgmt_role_arn mgmt_role_region mgmt_role_duration mgmt_role_session_name
  export MGMT_ROLE_ARN="$mgmt_role_arn"
  export MGMT_ROLE_REGION="$mgmt_role_region"
  export MGMT_ROLE_DURATION="$mgmt_role_duration"
  export MGMT_ROLE_SESSION_NAME="$mgmt_role_session_name"

  # AWS creds: only set from config if not already provided by flags or env
  if [[ -z "${AWS_ACCESS_KEY_ID:-}" && -z "${ACCESS_KEY:-}" ]]; then
    AWS_ACCESS_KEY_ID="$(aws_cfg_get aws_access_key_id || true)"
  fi
  if [[ -z "${AWS_SECRET_ACCESS_KEY:-}" && -z "${SECRET_KEY:-}" ]]; then
    AWS_SECRET_ACCESS_KEY="$(aws_cfg_get aws_secret_access_key || true)"
  fi
  if [[ -z "${AWS_SESSION_TOKEN:-}" && -z "${SESSION_TOKEN:-}" ]]; then
    AWS_SESSION_TOKEN="$(aws_cfg_get aws_session_token || true)"
  fi

  # Optional default for pre-assume role from config
  if [[ -z "${PRE_ASSUME_ROLE_ARN:-}" ]]; then
    PRE_ASSUME_ROLE_ARN="$(aws_cfg_get pre_assume_role_arn || true)"
  fi
}

# Pre-assume a member-account role and export its temp creds
assume_role_export() {
  local role_arn="$1"
  local session_name="$2"
  local duration="$3"

  command -v aws >/dev/null 2>&1 || { print_message "$RED" "AWS CLI v2 is required for pre-assume."; exit 1; }

  print_message "$YELLOW" "Pre-assuming role: ${role_arn}"

  # One call → get AK, SK, TK, EXP all at once (tab-separated)
  local line
  if ! line="$(aws sts assume-role \
      --role-arn "$role_arn" \
      --role-session-name "$session_name" \
      --duration-seconds "$duration" \
      --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken,Expiration]' \
      --output text 2>/dev/null)"; then
    print_message "$RED" "Failed to assume role ${role_arn}."
    exit 1
  fi

  # Split into variables
  local AK SK TK EXP
  IFS=$'\t' read -r AK SK TK EXP <<< "$line"

  if [[ -z "$AK" || -z "$SK" || -z "$TK" ]]; then
    print_message "$RED" "AssumeRole did not return a complete credential set."
    exit 1
  fi

  export AWS_ACCESS_KEY_ID="$AK"
  export AWS_SECRET_ACCESS_KEY="$SK"
  export AWS_SESSION_TOKEN="$TK"

  print_message "$YELLOW" "  assumed: ${role_arn}"
  print_message "$YELLOW" "  expires: ${EXP}"
  print_message "$YELLOW" "  aws_access_key_id = ${AWS_ACCESS_KEY_ID:0:4}********"
}

# ────────────────────────────────────────────────────────────────────────────────
# Apply CLI flags for creds first (highest precedence)
# ────────────────────────────────────────────────────────────────────────────────
if [[ -n "${ACCESS_KEY}" ]]; then export AWS_ACCESS_KEY_ID="$ACCESS_KEY"; fi
if [[ -n "${SECRET_KEY}" ]]; then export AWS_SECRET_ACCESS_KEY="$SECRET_KEY"; fi
if [[ -n "${SESSION_TOKEN}" ]]; then export AWS_SESSION_TOKEN="$SESSION_TOKEN"; fi

# Load from ~/.aws/config (respects existing env/flags)
load_mgmt_role_and_creds_from_config

# ────────────────────────────────────────────────────────────────────────────────
# Interactive prompts for config values (if not provided via CLI)
# ────────────────────────────────────────────────────────────────────────────────
# Only prompt if running interactively (stdin is a terminal)
if [[ -t 0 ]]; then
  # Prompt for region if not provided via CLI
  if [[ "$REGION_PROVIDED" == "false" ]]; then
    config_region="$(aws_cfg_get region || true)"
    if [[ -z "$config_region" ]]; then
      config_region="us-west-2"
    fi
    user_region="$(prompt_with_default "Region" "region" "$config_region" "AWS_REGION")"
    AWS_REGION="$user_region"
  fi
  
  # Prompt for mgmt_role_arn if not set and segregation check might run
  if [[ -z "${mgmt_role_arn:-}" ]]; then
    user_mgmt_arn="$(prompt_with_default "Management Role ARN (for segregation check, or press Enter to skip)" "mgmt_role_arn" "" "mgmt_role_arn")"
    if [[ -n "$user_mgmt_arn" ]]; then
      mgmt_role_arn="$user_mgmt_arn"
      export mgmt_role_arn MGMT_ROLE_ARN="$mgmt_role_arn"
      
      # Prompt for related mgmt role settings if not set
      if [[ -z "${mgmt_role_region:-}" ]] || [[ "$mgmt_role_region" == "us-east-1" ]]; then
        config_mgmt_region="$(aws_cfg_get mgmt_role_region || true)"
        if [[ -z "$config_mgmt_region" ]]; then
          # Auto-detect GovCloud if ARN suggests it
          if [[ "$mgmt_role_arn" == *"arn:aws-us-gov:"* ]]; then
            config_mgmt_region="us-gov-west-1"
          else
            config_mgmt_region="us-east-1"
          fi
        fi
        user_mgmt_region="$(prompt_with_default "Management Role Region" "mgmt_role_region" "$config_mgmt_region" "mgmt_role_region")"
        mgmt_role_region="$user_mgmt_region"
        export mgmt_role_region MGMT_ROLE_REGION="$mgmt_role_region"
      fi
      
      if [[ -z "${mgmt_role_duration:-}" ]] || [[ "$mgmt_role_duration" == "900" ]]; then
        config_mgmt_duration="$(aws_cfg_get mgmt_role_duration || true)"
        if [[ -z "$config_mgmt_duration" ]]; then
          config_mgmt_duration="900"
        fi
        user_mgmt_duration="$(prompt_with_default "Management Role Duration (seconds)" "mgmt_role_duration" "$config_mgmt_duration" "mgmt_role_duration")"
        mgmt_role_duration="$user_mgmt_duration"
        export mgmt_role_duration MGMT_ROLE_DURATION="$mgmt_role_duration"
      fi
      
      if [[ -z "${mgmt_role_session_name:-}" ]] || [[ "$mgmt_role_session_name" == "segregation-check" ]]; then
        config_mgmt_session="$(aws_cfg_get mgmt_role_session_name || true)"
        if [[ -z "$config_mgmt_session" ]]; then
          config_mgmt_session="segregation-check"
        fi
        user_mgmt_session="$(prompt_with_default "Management Role Session Name" "mgmt_role_session_name" "$config_mgmt_session" "mgmt_role_session_name")"
        mgmt_role_session_name="$user_mgmt_session"
        export mgmt_role_session_name MGMT_ROLE_SESSION_NAME="$mgmt_role_session_name"
      fi
    fi
  fi
  
  # Prompt for pre-assume role if not set
  if [[ -z "${PRE_ASSUME_ROLE_ARN:-}" ]]; then
    config_pre_assume="$(aws_cfg_get pre_assume_role_arn || true)"
    user_pre_assume="$(prompt_with_default "Pre-assume Role ARN (optional, press Enter to skip)" "pre_assume_role_arn" "$config_pre_assume" "PRE_ASSUME_ROLE_ARN")"
    if [[ -n "$user_pre_assume" ]]; then
      PRE_ASSUME_ROLE_ARN="$user_pre_assume"
    fi
  fi
fi

# Normalize empties and conditionally export AWS_* (all-or-nothing)
AWS_ACCESS_KEY_ID="$(printf "%s" "${AWS_ACCESS_KEY_ID:-}" | trim)"
AWS_SECRET_ACCESS_KEY="$(printf "%s" "${AWS_SECRET_ACCESS_KEY:-}" | trim)"
AWS_SESSION_TOKEN="$(printf "%s" "${AWS_SESSION_TOKEN:-}" | trim)"

if [[ -n "${AWS_ACCESS_KEY_ID}" && -n "${AWS_SECRET_ACCESS_KEY}" ]]; then
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
  if [[ -n "${AWS_SESSION_TOKEN}" ]]; then
    export AWS_SESSION_TOKEN
  else
    unset AWS_SESSION_TOKEN 2>/dev/null || true
  fi
else
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN 2>/dev/null || true
fi

# Status printout (masked)
print_message "$YELLOW" "Loaded config from profile '${ACTIVE_PROFILE}':"
if [[ -n "${mgmt_role_arn:-}" ]]; then
  print_message "$YELLOW" "  mgmt_role_arn            = (set)"
else
  print_message "$YELLOW" "  mgmt_role_arn            = (not set)"
fi
print_message "$YELLOW" "  mgmt_role_region         = ${mgmt_role_region}"
print_message "$YELLOW" "  mgmt_role_duration       = ${mgmt_role_duration}"
print_message "$YELLOW" "  mgmt_role_session_name   = ${mgmt_role_session_name}"
if [[ -n "${PRE_ASSUME_ROLE_ARN:-}" ]]; then
  print_message "$YELLOW" "  pre_assume_role_arn      = ${PRE_ASSUME_ROLE_ARN}"
fi

if [[ -n "${AWS_ACCESS_KEY_ID:-}" ]]; then
  print_message "$YELLOW" "  aws_access_key_id        = ${AWS_ACCESS_KEY_ID:0:4}********"
  print_message "$YELLOW" "  aws_secret_access_key    = ******** (set)"
  print_message "$YELLOW" "  aws_session_token        = $( [[ -n "${AWS_SESSION_TOKEN:-}" ]] && echo '******** (set)' || echo '(not set)' )"
else
  print_message "$YELLOW" "  aws_access_key_id        = (not set)"
  print_message "$YELLOW" "  aws_secret_access_key    = (not set)"
  print_message "$YELLOW" "  aws_session_token        = (not set)"
fi

# ────────────────────────────────────────────────────────────────────────────────
# Optional pre-assume of member-account role (e.g., KovrAuditRole)
# ────────────────────────────────────────────────────────────────────────────────
if [[ -n "${PRE_ASSUME_ROLE_ARN:-}" ]]; then
  # If we *don't* already have full env creds, let the CLI use profile/SSO to assume
  if [[ -z "${AWS_ACCESS_KEY_ID:-}" || -z "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN 2>/dev/null || true
  fi
  assume_role_export "$PRE_ASSUME_ROLE_ARN" "$PRE_ASSUME_SESSION_NAME" "$PRE_ASSUME_DURATION"
  # Verify the env creds we just exported are valid
  if ! aws sts get-caller-identity >/dev/null 2>&1; then
    print_message "$RED" "Post-assume STS call failed; environment credentials are invalid."
    exit 1
  fi

else
  print_message "$YELLOW" "No pre-assume role provided; proceeding with current identity."
fi

# ────────────────────────────────────────────────────────────────────────────────
# Prepare runtime
# ────────────────────────────────────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR"

print_message "$YELLOW" "Setting up Python virtual environment..."
if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
fi
# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

print_message "$YELLOW" "Installing required Python packages..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

# Build args for Python
PYTHON_ARGS=(
  "--region" "$AWS_REGION"
  "--output-dir" "$OUTPUT_DIR"
  "--format" "$FORMAT"
  "$PARALLEL"
  "--workers" "$WORKERS"
)

if [[ -n "$GIT_REPO" ]]; then
  PYTHON_ARGS+=("--git-repo" "$GIT_REPO" "--git-branch" "$GIT_BRANCH")
fi
if [[ -n "$SEVERITY" ]]; then
  PYTHON_ARGS+=("--severity" "$SEVERITY")
fi
if [[ -n "$CHECKS" ]]; then
  IFS=',' read -ra CHECK_ARRAY <<< "$CHECKS"
  for check in "${CHECK_ARRAY[@]}"; do
    PYTHON_ARGS+=("--checks" "$check")
  done
fi
if [[ -n "$SKIP_CHECKS" ]]; then
  IFS=',' read -ra SKIP_ARRAY <<< "$SKIP_CHECKS"
  for skip in "${SKIP_ARRAY[@]}"; do
    PYTHON_ARGS+=("--skip-checks" "$skip")
  done
fi

# ────────────────────────────────────────────────────────────────────────────────
# Run
# ────────────────────────────────────────────────────────────────────────────────
print_message "$GREEN" "Starting compliance checks..."
python3 src/main.py "${PYTHON_ARGS[@]}"
EXIT_CODE=$?

deactivate || true

if [[ $EXIT_CODE -eq 0 ]]; then
  print_message "$GREEN" "✓ Compliance checks completed successfully!"
elif [[ $EXIT_CODE -eq 1 ]]; then
  print_message "$YELLOW" "⚠ Compliance checks completed with failures."
else
  print_message "$RED" "✗ Error occurred during compliance checks."
fi

print_message "$BLUE" "Reports generated in: $OUTPUT_DIR"
exit $EXIT_CODE
