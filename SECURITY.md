# Security policy

## Supported versions

Security fixes are applied to the current release line and the `develop` branch. Release candidates are provided for testing before a stable release and should not be treated as production-ready until promoted.

| Version | Supported |
| --- | --- |
| Latest stable release | Yes |
| Current release candidate | Testing only |
| `develop` | Development testing |
| Older releases | No |

## Report a vulnerability

Please use [GitHub private vulnerability reporting](https://github.com/mangyan1/NPMplus/security/advisories/new). Do not open a public issue for an undisclosed vulnerability.

Include the affected version or commit, configuration, reproduction steps, impact, and any proposed mitigation. Remove passwords, tokens, private keys, domain names, and public IP addresses from logs before attaching them.

This fork includes upstream NPMplus and Nginx Proxy Manager code. Reports that only affect an unchanged upstream component may also need coordinated disclosure to that project's maintainers. Please give this fork a reasonable opportunity to investigate before public disclosure.
