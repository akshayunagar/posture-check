#!/usr/bin/env bash
# Collect host facts as JSON for posture-check's host-hygiene check.
#
# Deliberately small and readable: this is the only part that runs with
# privileges, so it should be auditable at a glance. It reads; it never writes
# outside stdout and never phones home.
#
#   sudo ./collect/host_facts.sh > facts/web01.json
set -euo pipefail

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# --- accounts -------------------------------------------------------------
accounts="[]"
if [[ -r /etc/passwd ]]; then
  accounts=$(awk -F: '$1 != "nobody" {
      printf "%s{\"name\":\"%s\",\"uid\":%s,\"shell\":\"%s\"}", (NR>1?",":""), $1, $3, $7
    }' /etc/passwd)
  accounts="[${accounts}]"
fi

# --- passwordless sudo ----------------------------------------------------
sudo_entries=""
if [[ -r /etc/sudoers ]]; then
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    entry=$(printf '%s' "$line" | awk '{print $1}')
    sudo_entries+="${sudo_entries:+,}\"$(json_escape "$entry")\""
  done < <(grep -rhE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true)
fi

# --- pending updates ------------------------------------------------------
upgradable="[]"
if command -v apt-get >/dev/null 2>&1; then
  pkgs=""
  while IFS= read -r line; do
    name=${line%%/*}
    [[ -n "$name" && "$name" != "Listing..." ]] || continue
    sec=false
    [[ "$line" == *-security* ]] && sec=true
    pkgs+="${pkgs:+,}{\"name\":\"$(json_escape "$name")\",\"security\":$sec}"
  done < <(apt list --upgradable 2>/dev/null | tail -n +2 || true)
  upgradable="[${pkgs}]"
fi

# --- world-writable files (outside the usual temp dirs) -------------------
ww=""
while IFS= read -r path; do
  ww+="${ww:+,}\"$(json_escape "$path")\""
done < <(find / -xdev -type f -perm -0002 \
           -not -path '/tmp/*' -not -path '/var/tmp/*' -not -path '/proc/*' \
           2>/dev/null | head -n 50 || true)

# --- sensitive files readable by everyone ---------------------------------
secrets=""
for candidate in /etc/shadow /etc/ssh/ssh_host_rsa_key /root/.ssh/id_rsa; do
  if [[ -f "$candidate" ]] && [[ $(stat -c '%a' "$candidate" 2>/dev/null || echo 600) =~ [0-9][0-9][4-7] ]]; then
    secrets+="${secrets:+,}\"$(json_escape "$candidate")\""
  fi
done

cat <<JSON
{
  "collected_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "hostname": "$(hostname)",
  "accounts": ${accounts},
  "passwordless_sudo": [${sudo_entries}],
  "upgradable_packages": ${upgradable},
  "world_writable_files": [${ww}],
  "readable_secrets": [${secrets}]
}
JSON
