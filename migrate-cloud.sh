#!/usr/bin/env bash
set -euo pipefail
umask 077

# One-time legacy flat-layout migration. This script is intentionally separate
# from install-cloud.sh; normal installation and future updates never scan the
# host or infer an installation directory.
BRAND_ID="${POLYNEXUS_UPDATE_BRAND_ID:-polynexus}"
APP_NAME="${POLYNEXUS_UPDATE_APP_NAME:-PolyNexus}"
RELEASE_REPO="${POLYNEXUS_UPDATE_RELEASE_REPO:-lddb1900/polynexus}"
CLOUD_EXECUTABLE="${POLYNEXUS_UPDATE_CLOUD_EXECUTABLE:-PolyNexusCloud}"
MIGRATION_ENV_FILE="${POLYNEXUS_ENV_FILE:-/etc/${BRAND_ID}/cloud.env}"

die() { printf '%s\n' "$*" >&2; exit 1; }

SOURCE_DIR=""
INSTALLER_SOURCE=""
AUTO_DISCOVER=0
SUPERVISOR_MODE="baota"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --source-dir) SOURCE_DIR="$2"; shift 2 ;;
    --installer) INSTALLER_SOURCE="$2"; shift 2 ;;
    --auto) AUTO_DISCOVER=1; shift ;;
    --supervisor) SUPERVISOR_MODE="$2"; shift 2 ;;
    *) die "Usage: migrate-cloud.sh (--source-dir PATH | --auto) [--installer PATH] [--supervisor MODE]" ;;
  esac
done

[[ "$EUID" -eq 0 ]] || die "Run this migration once as root, for example: sudo bash migrate-cloud.sh --auto"
[[ -n "$SOURCE_DIR" || "$AUTO_DISCOVER" == "1" ]] || die "Specify --source-dir or --auto."
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required for legacy installation verification."
command -v curl >/dev/null 2>&1 || die "curl is required for legacy migration."

normalize_dir() {
  local value="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath -m "$value"
  else
    readlink -m "$value"
  fi
}

is_legacy_candidate() {
  local candidate="$1" expected actual manifest
  [[ -d "$candidate" ]] || return 1
  [[ -x "$candidate/$CLOUD_EXECUTABLE" ]] || return 1
  manifest="$candidate/${CLOUD_EXECUTABLE}.integrity.json"
  [[ -f "$manifest" ]] || return 1
  expected="$(sed -n 's/.*"sha256"[[:space:]]*:[[:space:]]*"\([0-9a-fA-F]\{64\}\)".*/\1/p' "$manifest" | head -n 1 | tr 'A-F' 'a-f')"
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || return 1
  actual="$(sha256sum "$candidate/$CLOUD_EXECUTABLE" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] || return 1
  [[ ! -f "$candidate/.cloud-install-root" ]] || return 1
  [[ "$candidate" != */releases/* ]] || return 1
  [[ -f "$candidate/config.toml" ]] || return 1
  [[ -f "$candidate/bt-cloud-guard.sh" ]] || return 1
  bash -n "$candidate/bt-cloud-guard.sh" >/dev/null 2>&1 || return 1
}

read_persisted_master_key() {
  [[ -f "$MIGRATION_ENV_FILE" ]] || return 0
  (
    unset POLYNEXUS_MASTER_KEY
    set -a
    # shellcheck disable=SC1090
    source "$MIGRATION_ENV_FILE"
    set +a
    printf '%s' "${POLYNEXUS_MASTER_KEY:-}"
  ) 2>/dev/null || true
}

persist_migration_master_key() {
  local key_value="$1"
  local env_dir
  [[ -n "$key_value" ]] || return 1
  env_dir="$(dirname "$MIGRATION_ENV_FILE")"
  umask 077
  mkdir -p "$env_dir"
  if [[ -f "$MIGRATION_ENV_FILE" ]]; then
    printf '\nPOLYNEXUS_MASTER_KEY=%q\n' "$key_value" >> "$MIGRATION_ENV_FILE"
  else
    printf 'POLYNEXUS_MASTER_KEY=%q\n' "$key_value" > "$MIGRATION_ENV_FILE"
  fi
  chmod 600 "$MIGRATION_ENV_FILE" 2>/dev/null || true
}

read_process_environment_value() {
  local pid="$1" variable_name="$2"
  [[ "$pid" =~ ^[0-9]+$ && -r "/proc/$pid/environ" ]] || return 0
  tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null \
    | awk -v prefix="${variable_name}=" \
        'index($0, prefix) == 1 { value = substr($0, length(prefix) + 1) } END { printf "%s", value }'
}

read_process_master_key() {
  read_process_environment_value "$1" POLYNEXUS_MASTER_KEY
}

read_persisted_runtime_value() {
  local variable_name="$1"
  [[ -f "$MIGRATION_ENV_FILE" ]] || return 0
  (
    unset XDG_STATE_HOME
    set -a
    # shellcheck disable=SC1090
    source "$MIGRATION_ENV_FILE"
    set +a
    case "$variable_name" in
      XDG_STATE_HOME) printf '%s' "${XDG_STATE_HOME:-}" ;;
      *) return 1 ;;
    esac
  ) 2>/dev/null || true
}

read_process_uid() {
  local pid="$1"
  [[ "$pid" =~ ^[0-9]+$ && -r "/proc/$pid/status" ]] || return 0
  awk '/^Uid:/ { printf "%s", $2; exit }' "/proc/$pid/status" 2>/dev/null || true
}

verify_secret_storage_continuity() {
  local config_path="$1" running_key="${2:-}" current_key="${POLYNEXUS_MASTER_KEY:-}"
  local persisted_key="" effective_key=""
  [[ -f "$config_path" ]] || return 0
  if grep -Fq 'enc:dpapi:' "$config_path"; then
    die "The legacy config contains Windows DPAPI secrets and cannot be migrated to Linux. Re-enter the live credentials on Linux instead."
  fi
  grep -Fq 'enc:aesgcm:v1:' "$config_path" || return 0
  persisted_key="$(read_persisted_master_key)"
  if [[ -n "$running_key" && -n "$current_key" && "$running_key" != "$current_key" ]]; then
    die "The supplied POLYNEXUS_MASTER_KEY differs from the key used by the running legacy process."
  fi
  if [[ -n "$current_key" && -n "$persisted_key" && "$current_key" != "$persisted_key" ]]; then
    if [[ -z "$running_key" ]]; then
      die "POLYNEXUS_MASTER_KEY differs from the persisted key in $MIGRATION_ENV_FILE. Refusing to migrate encrypted credentials."
    fi
  fi
  effective_key="${running_key:-${current_key:-$persisted_key}}"
  if [[ -z "$effective_key" ]]; then
    die "The legacy config contains encrypted credentials. Export the exact original POLYNEXUS_MASTER_KEY or restore it in $MIGRATION_ENV_FILE before migration."
  fi
  if [[ "$effective_key" != "$persisted_key" ]]; then
    persist_migration_master_key "$effective_key" \
      || die "Unable to persist the existing POLYNEXUS_MASTER_KEY to $MIGRATION_ENV_FILE."
  fi
}

declare -A CANDIDATES=()
add_candidate() {
  local candidate
  candidate="$(normalize_dir "$1")"
  if is_legacy_candidate "$candidate"; then
    CANDIDATES["$candidate"]=1
  fi
}

discover_from_processes() {
  local proc cmdline cwd exe_path
  for proc in /proc/[0-9]*; do
    [[ -r "$proc/cmdline" ]] || continue
    cmdline="$(tr '\0' ' ' < "$proc/cmdline" 2>/dev/null || true)"
    [[ "$cmdline" == *"$CLOUD_EXECUTABLE"* ]] || continue
    exe_path="$(printf '%s' "$cmdline" | grep -oE "/[^ ]*/${CLOUD_EXECUTABLE}" | head -n 1 || true)"
    [[ -n "$exe_path" ]] && add_candidate "$(dirname "$exe_path")"
    cwd="$(readlink -f "$proc/cwd" 2>/dev/null || true)"
    [[ -n "$cwd" ]] && add_candidate "$cwd"
  done
}

discover_from_files() {
  local root executable
  for root in /opt /www /srv /home /root; do
    [[ -d "$root" ]] || continue
    while IFS= read -r executable; do
      add_candidate "$(dirname "$executable")"
    done < <(find "$root" -xdev -type f -name "$CLOUD_EXECUTABLE" -perm /111 2>/dev/null || true)
  done
}

if [[ -n "$SOURCE_DIR" ]]; then
  SOURCE_DIR="$(normalize_dir "$SOURCE_DIR")"
  is_legacy_candidate "$SOURCE_DIR" || die "The specified directory is not a valid legacy $APP_NAME cloud installation: $SOURCE_DIR"
else
  discover_from_processes
  discover_from_files
  if [[ ${#CANDIDATES[@]} -ne 1 ]]; then
    printf 'Unable to select one legacy installation automatically. Valid candidates:\n' >&2
    for candidate in "${!CANDIDATES[@]}"; do printf '  %s\n' "$candidate" >&2; done
    die "Run again with --source-dir PATH."
  fi
  for candidate in "${!CANDIDATES[@]}"; do SOURCE_DIR="$candidate"; done
fi

TARGET_DIR="$SOURCE_DIR"
printf 'Migrating the verified legacy installation in place: %s\n' "$TARGET_DIR"

ACTIVE_PID=""
for proc in /proc/[0-9]*; do
  [[ -r "$proc/cmdline" ]] || continue
  cmdline="$(tr '\0' ' ' < "$proc/cmdline" 2>/dev/null || true)"
  [[ "$cmdline" == *"$CLOUD_EXECUTABLE"* && "$cmdline" != *"--worker"* ]] || continue
  cwd="$(readlink -f "$proc/cwd" 2>/dev/null || true)"
  exe_path="$(printf '%s' "$cmdline" | grep -oE "/[^ ]*/${CLOUD_EXECUTABLE}" | head -n 1 || true)"
  if [[ "$cwd" == "$TARGET_DIR" || ( -n "$exe_path" && "$(dirname "$exe_path")" == "$TARGET_DIR" ) ]]; then
    ACTIVE_PID="${proc##*/}"
    break
  fi
done

# Encrypted cloud credentials can only survive migration when the exact same
# master key survives it. Compare the caller, persisted environment file and
# the key actually inherited by the running legacy supervisor before writing
# any new-layout files.
RUNNING_MASTER_KEY="$(read_process_master_key "$ACTIVE_PID")"
LEGACY_RUNTIME_UID="$(read_process_uid "$ACTIVE_PID")"
if [[ -n "$LEGACY_RUNTIME_UID" && "$LEGACY_RUNTIME_UID" != "0" ]]; then
  LEGACY_RUNTIME_USER="$(getent passwd "$LEGACY_RUNTIME_UID" 2>/dev/null | cut -d: -f1 || true)"
  printf '%s\n' \
    "Warning: the legacy runtime is owned by ${LEGACY_RUNTIME_USER:-UID $LEGACY_RUNTIME_UID}. The managed cloud runtime runs as root, so its user-scoped activation must be completed again after migration." \
    >&2
fi
verify_secret_storage_continuity "$TARGET_DIR/config.toml" "$RUNNING_MASTER_KEY"
verify_secret_storage_continuity "$TARGET_DIR/okx_futures.toml" "$RUNNING_MASTER_KEY"

mkdir -p "$TARGET_DIR/shared"
for persistent_file in \
  config.toml \
  okx_futures.toml \
  cloud_web_auth.json \
  config.toml.cloud-automation-guard.json; do
  if [[ -f "$TARGET_DIR/$persistent_file" && ! -f "$TARGET_DIR/shared/$persistent_file" ]]; then
    cp -p "$TARGET_DIR/$persistent_file" "$TARGET_DIR/shared/$persistent_file"
    chmod 0600 "$TARGET_DIR/shared/$persistent_file"
  fi
done
# The new runtime resolves relative database paths beside shared/config.toml.
# Symlinks preserve the exact live database files without copying SQLite while
# the legacy process is running. They can be replaced with real files during a
# later planned maintenance window if desired.
for database_file in "$TARGET_DIR"/*.sqlite3 "$TARGET_DIR"/*.sqlite3-shm "$TARGET_DIR"/*.sqlite3-wal; do
  [[ -e "$database_file" ]] || continue
  database_name="$(basename "$database_file")"
  [[ -e "$TARGET_DIR/shared/$database_name" ]] || ln -s "../$database_name" "$TARGET_DIR/shared/$database_name"
done

# Wallet-vault delivery state is outside the installation directory and its
# file name is keyed by the absolute config path. Bridge the old flat config
# identity to shared/config.toml once so an encrypted pending envelope and the
# device signing identity survive this one-time migration. Normal installs and
# updates never need this compatibility step.
migrate_wallet_vault_runtime_state() {
  local legacy_state_home="$1" managed_state_home="$2"
  local legacy_state_dir managed_state_dir
  local old_config new_config old_identity new_identity old_path new_path suffix
  legacy_state_home="$(normalize_dir "$legacy_state_home")"
  managed_state_home="$(normalize_dir "$managed_state_home")"
  legacy_state_dir="$legacy_state_home/${BRAND_ID}/runtime-state"
  managed_state_dir="$managed_state_home/${BRAND_ID}/runtime-state"
  old_config="$(normalize_dir "$TARGET_DIR/config.toml")"
  new_config="$(normalize_dir "$TARGET_DIR/shared/config.toml")"
  old_identity="$(printf '%s' "$old_config" | sha256sum | awk '{print $1}')"
  new_identity="$(printf '%s' "$new_config" | sha256sum | awk '{print $1}')"
  [[ "$old_identity" != "$new_identity" && -d "$legacy_state_dir" ]] || return 0
  mkdir -p "$managed_state_dir"
  chmod 0700 "$managed_state_dir" 2>/dev/null || true
  for suffix in pending device; do
    if [[ "$suffix" == "pending" ]]; then
      old_path="$legacy_state_dir/.pending-${old_identity}.dat"
      new_path="$managed_state_dir/.pending-${new_identity}.dat"
    else
      old_path="$legacy_state_dir/.device-${old_identity}.dat.key"
      new_path="$managed_state_dir/.device-${new_identity}.dat.key"
    fi
    if [[ -e "$old_path" && ! -e "$new_path" ]]; then
      ln -s "$old_path" "$new_path"
    fi
  done
}

RUNNING_XDG_STATE_HOME="$(read_process_environment_value "$ACTIVE_PID" XDG_STATE_HOME)"
RUNNING_HOME="$(read_process_environment_value "$ACTIVE_PID" HOME)"
PERSISTED_XDG_STATE_HOME="$(read_persisted_runtime_value XDG_STATE_HOME)"
MANAGED_STATE_HOME="${PERSISTED_XDG_STATE_HOME:-/root/.local/state}"
if [[ -n "$RUNNING_XDG_STATE_HOME" ]]; then
  LEGACY_STATE_HOME="$RUNNING_XDG_STATE_HOME"
elif [[ -n "$RUNNING_HOME" ]]; then
  LEGACY_STATE_HOME="$RUNNING_HOME/.local/state"
else
  LEGACY_STATE_HOME="$MANAGED_STATE_HOME"
fi
migrate_wallet_vault_runtime_state "$LEGACY_STATE_HOME" "$MANAGED_STATE_HOME"

# Legacy builds did not consistently publish a machine-readable version. They
# are therefore never registered as a rollback release. The old executable is
# used only to verify that the selected directory is a genuine legacy install;
# persistent files are migrated above and the standard installer now downloads
# the latest verified GitHub Release as the first managed software version.
rm -f "$TARGET_DIR/current.migration"

INSTALLER_PATH="$TARGET_DIR/install-cloud.sh"
if [[ -n "$INSTALLER_SOURCE" ]]; then
  INSTALLER_SOURCE="$(normalize_dir "$INSTALLER_SOURCE")"
  [[ -f "$INSTALLER_SOURCE" ]] || die "Installer script not found: $INSTALLER_SOURCE"
  cp "$INSTALLER_SOURCE" "$INSTALLER_PATH.new"
else
  curl --fail --location --connect-timeout 10 --max-time 30 \
    -o "$INSTALLER_PATH.new" "https://raw.githubusercontent.com/${RELEASE_REPO}/main/install-cloud.sh"
fi
chmod 0755 "$INSTALLER_PATH.new"
mv -f "$INSTALLER_PATH.new" "$INSTALLER_PATH"

export POLYNEXUS_INSTALL_ROOT="$TARGET_DIR"
if [[ -n "$ACTIVE_PID" ]]; then
  export POLYNEXUS_RUNTIME_SUPERVISOR_PID="$ACTIVE_PID"
fi
bash "$INSTALLER_PATH" --install-dir "$TARGET_DIR" --supervisor "$SUPERVISOR_MODE" install
printf '%s legacy migration completed. Future updates use %s only.\n' "$APP_NAME" "$INSTALLER_PATH"
