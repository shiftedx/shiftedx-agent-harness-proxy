# Security policy

## Supported versions

This project is prerelease software. Security fixes currently target the latest commit on `main`;
there is no supported public image or stable release line yet.

## Reporting a vulnerability

Do not include credentials, private prompts, tool results, model output, hidden benchmark material,
or exploit data in a public issue. Contact the repository owner through a private security advisory
after the public repository is created. Until then, report privately to the Shiftedx maintainer who
provided this source tree.

Include the affected revision, deployment topology, minimal sanitized reproduction, impact, and
whether a credential may have been exposed. Revoke suspected credentials before waiting for a
response.

## Boundary

The proxy is policy middleware, not a tool sandbox. Operators remain responsible for authenticating
clients, securing transport, isolating the upstream, and sandboxing every client-side tool executor.
See the README security checklist and ADR 0001.

## Deployment profiles

- Local development uses `DEPLOYMENT_PROFILE=development`, may omit downstream authentication, and
  must remain bound to host loopback. It is not a production security boundary.
- Trusted internal deployments use `DEPLOYMENT_PROFILE=production`, a file-mounted downstream
  bearer token, an explicit fixed upstream URL, and private network policy.
- Public deployments use the same fail-closed production profile behind a trusted TLS ingress. The
  ingress should route only the supported `/v1` API paths and keep `/healthz`, `/readyz`, and
  `/metrics` on its management side. The application exposes readiness on the same internal listener
  rather than a separate management socket.

The supplied production Compose override publishes only to host loopback and applies a read-only
filesystem, a non-root user, dropped capabilities, `no-new-privileges`, and finite PID, CPU, and
memory limits. Do not replace the loopback publication with `0.0.0.0:8090` as a substitute for a
TLS ingress and network access control.
