#!/bin/sh
# Applies the application blocks the backend generates (ADR-0011).
#
# The backend has no nginx binary and this container has no database, so the
# handover is a file: the backend writes `apps.conf.staged` into the shared
# volume and this loop installs it. Installing means test-then-keep, never
# write-then-hope — a generated file nginx will not parse must not be able to
# take the proxy down at its next restart, which is exactly what writing
# straight to apps.conf would allow.
#
# The 2 s poll is also the debounce ADR-0011 asks for: ten applications edited
# in a burst cost one reload, not ten, and every reload leaves a worker behind
# for as long as any long-lived connection is open (docs/07).

DIR=/etc/nginx/conf.d/generated
mkdir -p "$DIR"

reload_loop() {
    while true; do
        if [ -f "$DIR/apps.conf.staged" ]; then
            [ -f "$DIR/apps.conf" ] && cp "$DIR/apps.conf" "$DIR/apps.conf.bak"
            mv "$DIR/apps.conf.staged" "$DIR/apps.conf"
            if error=$(nginx -t 2>&1); then
                nginx -s reload
                echo "ok $(date -Iseconds)" > "$DIR/apps.status"
                echo "generated config applied and nginx reloaded" >&2
            else
                # The rollback is the point of the whole dance.
                if [ -f "$DIR/apps.conf.bak" ]; then
                    mv "$DIR/apps.conf.bak" "$DIR/apps.conf"
                else
                    rm -f "$DIR/apps.conf"
                fi
                printf 'invalid %s\n%s\n' "$(date -Iseconds)" "$error" > "$DIR/apps.status"
                echo "generated config rejected, previous config still in effect" >&2
            fi
            rm -f "$DIR/apps.conf.bak"
        fi
        sleep 2
    done
}

reload_loop &
