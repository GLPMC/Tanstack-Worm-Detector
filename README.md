# Mini Shai-Hulud Hunter (TanStack, 2026-05-11)

Detection script for the Mini Shai-Hulud npm worm that compromised 84 `@tanstack/*` package versions and 16 adjacent packages on 2026-05-11 at approximately 19:20 UTC.

Built by Groom Lake PMC. Read-only. No network calls. Linux + macOS.

## What it detects

Six independent checks, any of which alone is sufficient to suspect compromise:

1. **Filesystem scan** for the worm's dropper filenames (`router_init.js`, `router_runtime.js`, `tanstack_runner.js`, `setup.mjs`) with SHA256 verification against the known `router_init.js` hash.
2. **Lockfile scan** for any of the 100 compromised package@version pairs across `package-lock.json` (v1/v2/v3), `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, and `bun.lockb`.
3. **Installed `node_modules` version check** — catches stale installs even after lockfiles are cleaned.
4. **Malicious git-dependency marker** — `@tanstack/setup` optionalDependency pointing at commit `79ac49eedf774dd4b0cfa308722bc463cfe5885c`, in any `package.json` or lockfile.
5. **Credential staging artifacts** — `~/.npmrc` publish-token presence, dropper files in `.claude/` / `.vscode/` / `/tmp`, local git repos with commits by the malicious actor `voicproducoes`.
6. **GitHub Actions workflow tampering** — workflows referencing `shai-hulud`, `tanstack_runner`, `router_runtime`, or `setup.mjs`.

## Usage

```bash
chmod +x shai-hulud-hunt.sh
./shai-hulud-hunt.sh                  # scans $PWD
./shai-hulud-hunt.sh ~/code           # scans a specific path
./shai-hulud-hunt.sh /                # full host sweep (slow but thorough)
```

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Clean — no IOCs found |
| 1 | Suspicious indicators present, manual review needed |
| 2 | True positive likely — follow the printed remediation block |

## Read this before rotating any tokens

This worm family carries a **dead-man wiper**. If the payload loses both its npm and GitHub exfil/propagation channels while still resident on disk, it can detonate a destructive routine that runs `find ~ -type f -writable -user $USER -print0 | xargs -0 shred -uvz -n 1`. No recovery.

**Standard "rotate tokens immediately" guidance is wrong for this attack.** The script prints a four-phase remediation in the correct order when a severe finding fires:

1. **Contain** — egress-isolate the host at the network firewall, snapshot for forensics, remove worm artifacts.
2. **Kill CI/CD persistence** — delete rogue self-hosted runners, remove tampered workflows, revoke the OIDC trust at the npm trusted-publishers side.
3. **Rotate** — AWS → Vault → k8s → cloud creds → GitHub PATs → npm tokens, in that order. npm and GitHub tokens come last because rotating them is what trips the wiper.
4. **Hunt** — GitHub audit log review, outbound traffic analysis, SIEM correlation.

## Example output (true positive)

See [`example-true-positive-output.txt`](example-true-positive-output.txt) for a realistic SEVERE-finding run.

## Sources

- Socket Research Team — https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack
- StepSecurity — https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem
- TanStack incident issue — https://github.com/TanStack/router/issues/7383
- Kaspersky on wiper behavior in this worm family — https://securelist.com/shai-hulud-2-0/118214/

## Limitations

- The `router_init.js` SHA256 (`ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`) and `@tanstack/setup` `package.json` SHA256 (`7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b`) are sourced from Socket and StepSecurity respectively. They have not been independently cross-verified against a second researcher's published hash. If a dropper file is found whose hash doesn't match, do not assume it's safe — verify the file content manually.
- The 100-package list reflects what's published as of 2026-05-12. The campaign is still spreading. Re-check Socket's feed before declaring a host clean: https://app.stepsecurity.io/oss-security-feed
- The script does not detect bun-binary lockfile (`bun.lockb`) contents beyond filename presence, since it's a binary format. If a `bun.lockb` is present, additionally run `bun install --dry-run` against a pinned-clean `package.json` and review the output.
- The script does not parse `package-lock.json` lockfile v1 deeply for nested transitive dependencies. If your project predates npm 7, manually run `npm ls @tanstack/setup` to verify.

## License

Internal use. Distribute freely.
