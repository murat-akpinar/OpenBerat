# samba-ad

The lab directory (ADR-0010). A stock image, so there is no Dockerfile; the
service is defined in `docker-compose.yml`.

| File | Contents |
|---|---|
| `fixture.sh` | Every object Phase 1 measures against — OUs, the Keycloak bind account, the `OpenBerat-` groups, a nested group, a disabled account, and the comma-named group ADR-0008's filter has to exclude. |

Apply it once the DC has provisioned:

```sh
docker compose exec -T -e AD_BIND_PASSWORD -e LAB_USER_PASSWORD \
  samba-ad bash < samba-ad/fixture.sh
```

It runs inside the container and is safe to re-run: `samba-tool` has no
`--if-not-exists`, so the script treats "already exists" as success and every
other failure as one.

**The host cannot be a user namespace.** Provisioning writes `security.NTACL`,
which an unprivileged container refuses whatever capabilities it holds — bare
metal, a VM or a privileged container (`INSTALL.md` prerequisites, `docs/07`).
Check before starting the stack, as root on the host:

```sh
touch /tmp/x && python3 -c "import os; os.setxattr('/tmp/x','security.NTACL',b'\0')"
```

If that raises, `docker compose up` will get as far as a provisioned database
with no machine account and the container will restart forever.

**Lab only.** It ships in no release image, and the passwords in it are lab
passwords.
