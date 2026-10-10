# 0038 — One Docker network per protected application

- **Status:** Accepted
- **Date:** 2026-10-10
- **Relates to:** [0021](0021-application-identity-trusted-headers.md) — whose
  requirement ("the upstream is unreachable except from the PEP") this makes
  true between upstreams as well; [0030](0030-breakglass-generated-blocks.md) —
  break-glass joins the same networks.

## Context

ADR-0021 lets an application learn who the user is from `X-Auth-*` headers,
and promoted "the upstream is unreachable except from the PEP" to a product
requirement. `docs/02` drew two networks to meet it: `core` for the decision
chain and `edge` for nginx and **every** protected application.

That separates upstreams from the core, not from each other. Security audit
run-1 (2026-10-10) named it, and the lab confirmed it: a throwaway container on
`openberat_edge` sent `X-Auth-Groups: OpenBerat-Admins` straight to a neighbour
on the same network and the neighbour received it intact, no nginx in the path
(`docs/07`). Docker enables inter-container traffic on a user-defined bridge by
default, so one compromised application — or a careless one — can impersonate
any user, an administrator included, to every other trusted-header application
on the host.

## Options

| Option | Pro | Con |
|---|---|---|
| A. Keep `edge`, document the limit | No change | ADR-0021's requirement is false on any host with two applications |
| B. `enable_icc: false` on `edge` | One line | It cuts nginx off from the upstreams too — the bridge drops all container-to-container traffic |
| C. The backend creates a network per application | Automatic, follows the `application` table | Needs the Docker socket in the backend, which is root on the host in the component that faces every request |
| D. **One network per application, declared by the operator; nginx joins each** | Exactly the reachability ADR-0021 asks for, with nothing new running | One more step when an application is added, and a network per application on nginx |
| E. Signed identity JWT (ADR-0021 option C) | A bypass stops being impersonation | Most target applications (Jenkins first) cannot verify one; stays on the `Later` list |

## Decision

**D.** `edge` is gone. Each protected application sits on its own network,
`app-<slug>`, whose only other member is nginx (and `nginx-breakglass`, which
serves the same applications). The compose file does it for the two lab samples;
an installation declares its own in `docker-compose.override.yml`, as
`INSTALL.md` §7 shows, and tests it from a sibling application as well as from a
third machine. C was the automatic version and it is refused for the socket.

## Consequences

- Adding an application is now three things outside the API, not two: name
  resolution, the certificate, and its network. The admin API cannot check the
  third — it does not see Docker — so §7's test is the check.
- nginx carries one interface per application. A few dozen is unremarkable for
  Docker; a host with hundreds of applications should revisit E.
- An application on another machine is unchanged: its host firewall already
  admits only the proxy's address (§7).
- Reversing it is putting the applications back on one network; nothing is
  stored.
