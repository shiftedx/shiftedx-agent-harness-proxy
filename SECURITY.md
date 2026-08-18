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
