#!/bin/bash
# SPDX-FileCopyrightText: 2026 OpenBerat contributors
# SPDX-License-Identifier: GPL-3.0-or-later

# Does the running realm still match keycloak/realm/? Run it where
# docker-compose.yml is. Exit 0: it matches. 1: it drifted, and every setting
# that differs is printed. 2: the check itself could not run.
#
# "Matches" means identical to what a fresh import of the export produces in the
# same image, not "every key in the file has its value": the export names only
# what differs from Keycloak's defaults, so a setting switched on in the console
# that the file leaves at its default would pass a comparison against the file.
set -uo pipefail

REF=openberat-realm-reference
tmp=$(mktemp -d)
trap 'docker rm -f "$REF" >/dev/null 2>&1; rm -rf "$tmp"' EXIT

# Secrets come back as Keycloak's `**********` mask on both sides, so nothing
# compared here is a secret and no placeholder value has to be known.
# ponytail: signs in as the bootstrap admin from the service's environment; an
# installation that has retired that account needs another admin named here.
dump() {
  "$@" bash -c '/opt/keycloak/bin/kcadm.sh create \
    "realms/openberat/partial-export?exportClients=true&exportGroupsAndRoles=true" -o \
    --no-config --server http://localhost:8080 --realm master \
    --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD"' 2>/dev/null
}

dump docker compose exec -T keycloak > "$tmp/running.json" ||
  { echo "cannot read the running realm: is the keycloak service up?" >&2; exit 2; }

# --- Feature Start ---
# The reference must not touch the database the running realm lives in: the
# production form of the service (INSTALL.md §5) points KC_DB at it, and an
# import there is skipped at best. The variables are unset rather than emptied:
# an empty KC_DB_URL is a URL of "" to Keycloak, and it refuses to start
# (measured, docs/07). Its own H2 goes with the container on exit.
docker rm -f "$REF" > /dev/null 2>&1
docker compose --progress quiet run -d --no-deps --name "$REF" --entrypoint env keycloak \
  -u KC_DB_URL -u KC_DB_USERNAME -u KC_DB_PASSWORD KC_DB=dev-file \
  /opt/keycloak/bin/kc.sh start-dev --import-realm > /dev/null || exit 2
# --- Feature End ---

for _ in $(seq 100); do
  dump docker exec "$REF" > "$tmp/reference.json" && break
  if [ "$(docker inspect -f '{{.State.Running}}' "$REF")" != true ]; then
    echo "the export did not import:" >&2
    docker logs --tail 20 "$REF" >&2
    exit 2
  fi
  sleep 3
done
[ -s "$tmp/reference.json" ] || { echo "the reference Keycloak never answered" >&2; exit 2; }

python3 - "$tmp/reference.json" "$tmp/running.json" <<'EOF'
import json, sys

try:
    ref, run = (json.load(open(p)) for p in sys.argv[1:])
except ValueError:
    # Not drift: a realm that answered with something other than its export.
    print('a realm did not come back as JSON', file=sys.stderr)
    sys.exit(2)

# --- Feature Start ---
# The LDAP group mapper imports every AD group it matches as a realm group, so a
# live realm holds groups the export never names. One that carries nothing is
# that import; one that carries a role or an attribute was made by hand.
named = {g['name'] for g in ref.get('groups', [])}
imported = [g for g in run.get('groups', []) if g['name'] not in named
            and not any(g.get(k) for k in ('realmRoles', 'clientRoles', 'attributes', 'subGroups'))]
run['groups'] = [g for g in run.get('groups', []) if g not in imported]
# --- Feature End ---

# Any realm update through the admin API also stores four session timeouts as
# attributes, unchanged; the top-level field of the same name is compared.
for realm in (ref, run):
    realm['attributes'] = {k: v for k, v in realm.get('attributes', {}).items() if k not in realm}

GENERATED = {'id', 'containerId', 'parentId'}
NAMES = ('alias', 'clientId', 'username', 'name', 'authenticator', 'flowAlias')

def flatten(value, path, out):
    if isinstance(value, dict):
        for key, v in value.items():
            if key not in GENERATED:
                flatten(v, f'{path}.{key}' if path else key, out)
    elif isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
        seen = set()
        for i, v in enumerate(value):
            # Executions repeat an authenticator across priorities, and client
            # registration policies repeat a name across subTypes.
            parts = [v.get('subType'), next((v[k] for k in NAMES if k in v), i), v.get('priority')]
            label = '/'.join(str(p) for p in parts if p is not None)
            label = label if label not in seen else f'{label}#{i}'
            seen.add(label)
            flatten(v, f'{path}[{label}]', out)
    else:
        # Keycloak keeps most of these as sets and hands them back in any order.
        out[path] = sorted(value, key=json.dumps) if isinstance(value, list) else value

a, b = {}, {}
flatten(ref, '', a)
flatten(run, '', b)
drift = sorted(k for k in a.keys() | b.keys() if a.get(k, '<absent>') != b.get(k, '<absent>'))

for g in imported:
    print(f"not compared, imported from AD: group {g['name']}")
for k in drift:
    print(f"{k}\n  export:  {json.dumps(a.get(k, '<absent>'))}\n  running: {json.dumps(b.get(k, '<absent>'))}")
print(f'{len(drift)} settings differ from a fresh import of keycloak/realm/' if drift
      else 'the running realm is what keycloak/realm/ imports')
sys.exit(1 if drift else 0)
EOF
