#!/bin/sh
# SPDX-FileCopyrightText: 2026 OpenBerat contributors
# SPDX-License-Identifier: GPL-3.0-or-later

# Applies the application blocks the backend generates (ADR-0011, ADR-0030).
#
# The backend has no nginx binary and this container has no database, so the
# handover is a file: the backend writes `apps.conf.staged` and
# `breakglass.apps.staged` into the shared volume and this loop installs them.
# Installing means test-then-keep, never write-then-hope — a generated file
# nginx will not parse must not be able to take the proxy down at its next
# restart, which is exactly what writing straight to the live name would allow.
#
# The 2 s poll is also the debounce ADR-0011 asks for: ten applications edited
# in a burst cost one reload, not ten, and every reload leaves a worker behind
# for as long as any long-lived connection is open (docs/07).

DIR=/etc/nginx/conf.d/generated
mkdir -p "$DIR" 2>/dev/null

# --- Feature Start ---
# The break-glass container runs this same image and therefore this same script,
# and mounts the volume read-only — there is nothing for it to install, and a
# loop that cannot write would fill an incident's logs with failures every two
# seconds. It reads the file; it does not maintain it.
# --- Feature End ---
if [ ! -w "$DIR" ]; then
    echo "$DIR is read-only: reading generated blocks, not installing them" >&2
    return 0 2>/dev/null || exit 0
fi

# $1 live file name  ·  $2 status file  ·  $3 `nginx -t` target  ·  $4 reload?
install_staged() {
    live=$1
    status=$2
    target=$3
    reload=$4
    [ -f "$DIR/$live.staged" ] || return 0
    [ -f "$DIR/$live" ] && cp "$DIR/$live" "$DIR/$live.bak"
    mv "$DIR/$live.staged" "$DIR/$live"
    if error=$(nginx -t -c "$target" 2>&1); then
        [ "$reload" = reload ] && nginx -s reload
        echo "ok $(date -Iseconds)" > "$DIR/$status"
        echo "$live applied" >&2
    else
        # The rollback is the point of the whole dance.
        if [ -f "$DIR/$live.bak" ]; then
            mv "$DIR/$live.bak" "$DIR/$live"
        else
            rm -f "$DIR/$live"
        fi
        printf 'invalid %s\n%s\n' "$(date -Iseconds)" "$error" > "$DIR/$status"
        echo "$live rejected, the previous one is still in effect" >&2
    fi
    rm -f "$DIR/$live.bak"
}

reload_loop() {
    while true; do
        # The running configuration: install, test, reload.
        install_staged apps.conf apps.status /etc/nginx/nginx.conf reload
        # --- Feature Start ---
        # The break-glass twin (ADR-0030). Nothing is reloaded — no process is
        # running under that configuration — but it is still *tested*, with the
        # configuration it belongs to, because the moment it is read is the
        # moment nobody has time to debug it. `breakglass.conf` ships in this
        # image, so the container that installs the file can also parse it.
        # --- Feature End ---
        install_staged breakglass.apps breakglass.status /etc/nginx/breakglass.conf ""
        sleep 2
    done
}

reload_loop &
