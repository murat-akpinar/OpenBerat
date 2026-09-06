#!/bin/bash
# The lab AD fixture (ADR-0010): the objects every Phase 1 measurement runs
# against. It is a script and not a click-path because a measurement is only
# reproducible if the directory it ran in is.
#
# Runs *inside* the DC container, so it works wherever that container lives:
#
#   docker compose exec -T \
#     -e AD_BIND_PASSWORD -e LAB_USER_PASSWORD samba-ad bash < samba-ad/fixture.sh
#
# Re-running it is safe; see `try` below.
set -euo pipefail

: "${AD_BIND_PASSWORD:?set it, it is the Keycloak bind account password}"
: "${LAB_USER_PASSWORD:?set it, it is the password of every lab user}"

DOMAIN="${AD_DOMAIN:-example.local}"

# samba-tool has no --if-not-exists and exits 1 on a second run. That is the
# one failure that is not one; every other one still stops the fixture.
try() {
  local out
  if out=$("$@" 2>&1); then
    return 0
  fi
  grep -qiE "already exists|attribute or value exists" <<<"$out" || { printf '%s\n' "$out" >&2; return 1; }
}

try samba-tool ou create "OU=Users,DC=${DOMAIN//./,DC=}"
try samba-tool ou create "OU=Groups,DC=${DOMAIN//./,DC=}"
try samba-tool ou create "OU=Service Accounts,DC=${DOMAIN//./,DC=}"

# Keycloak binds as this one. AD has no read-only flag: it is read-only because
# it is a plain user in no privileged group and the provider is READ_ONLY.
try samba-tool user create svc-keycloak "$AD_BIND_PASSWORD" \
  --userou="OU=Service Accounts" --description="Keycloak LDAP bind (read-only)"
samba-tool user setexpiry svc-keycloak --noexpiry

for g in OpenBerat-Admins OpenBerat-Finance Finance-All; do
  try samba-tool group add "$g" --groupou="OU=Groups"
done

user() {
  try samba-tool user create "$1" "$LAB_USER_PASSWORD" --userou="OU=Users" \
    --given-name="$2" --surname="$3" --mail-address="$1@${DOMAIN}"
  samba-tool user setexpiry "$1" --noexpiry
}

user labuser     Lab User
user labadmin    Lab Admin
user labnested   Lab Nested
user labdisabled Lab Disabled

# AD does not delete leavers, it disables them. The custom user filter in the
# Keycloak provider is what keeps this account out; without the fixture having
# one, that filter is untested.
samba-tool user disable labdisabled

member() { try samba-tool group addmembers "$1" "$2"; }

member OpenBerat-Finance labuser
member OpenBerat-Admins  labadmin
member OpenBerat-Finance labadmin
member OpenBerat-Finance labdisabled

# Nested: labnested is in Finance-All, and Finance-All is a member of
# OpenBerat-Finance. `memberOf` on labnested therefore names Finance-All only,
# which is exactly the case GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE misses.
member OpenBerat-Finance Finance-All
member Finance-All       labnested

# --- Feature Start ---
# ADR-0008 mitigation 1 is the group filter `(cn=OpenBerat-*)`, and this is the
# thing it has to exclude: one group *named* `Payroll,OpenBerat-Admins` arrives
# in the comma-joined groups header as two, the second of which is ADMIN_GROUP
# (docs/07). The fixture ships the attack, not only the happy path.
#
# samba-tool cannot create it — it builds the DN by concatenation, so the comma
# ends the RDN (`invalid dn '(null)'`), and escaping it puts a backslash in
# sAMAccountName, which AD rejects. The comma is legal in `cn`, which is the
# attribute the group mapper reads, so the object goes in as LDIF with the DN
# escaped and sAMAccountName carrying an unremarkable name.
try ldbadd -H /var/lib/samba/private/sam.ldb <<LDIF
dn: CN=Payroll\\,OpenBerat-Admins,OU=Groups,DC=${DOMAIN//./,DC=}
objectClass: group
cn: Payroll,OpenBerat-Admins
sAMAccountName: payroll-escalation
groupType: -2147483646
LDIF
member payroll-escalation labuser
# --- Feature End ---

echo "fixture applied"
