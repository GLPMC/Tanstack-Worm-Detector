#!/usr/bin/env bash
# shai-hulud-hunt.sh
# Groom Lake PMC | Mini Shai-Hulud (TanStack, May 11 2026) detection
# Works on Linux + macOS. Read-only. No network calls.
#
# Refs:
#   socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack
#   stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem
#
# Usage: ./shai-hulud-hunt.sh [scan_root]
#   scan_root defaults to $PWD. Walks repos, node_modules, lockfiles, ~/.npmrc, /tmp.

set -u

ROOT="${1:-$PWD}"
HITS=0
SEVERE=0

# ---- colors (auto-disable if not a tty) -----------------------------------
if [ -t 1 ]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; B=$'\e[1m'; X=$'\e[0m'
else
  R=""; G=""; Y=""; C=""; B=""; X=""
fi

banner() {
cat <<'BANNER'
   ____                              _          _
  / ___|_ __ ___   ___  _ __ ___    | |    __ _| | _____
 | |  _| '__/ _ \ / _ \| '_ ` _ \   | |   / _` | |/ / _ \
 | |_| | | | (_) | (_) | | | | | |  | |__| (_| |   <  __/
  \____|_|  \___/ \___/|_| |_| |_|  |_____\__,_|_|\_\___|
                                                          
  Mini Shai-Hulud Hunter  |  TanStack worm, 2026-05-11
  ---------------------------------------------------------------
  WARNING: this worm family has a dead-man wiper. If a SEVERE
  finding fires, DO NOT rotate npm/GitHub tokens first. Read the
  remediation block printed at the end of this scan before acting.
  ---------------------------------------------------------------
BANNER
}

hit()    { HITS=$((HITS+1));   printf "%s[HIT]%s    %s\n"   "$Y" "$X" "$*"; }
severe() { SEVERE=$((SEVERE+1)); HITS=$((HITS+1)); printf "%s[SEVERE]%s %s\n" "$R" "$X" "$*"; }
info()   { printf "%s[i]%s     %s\n" "$C" "$X" "$*"; }
ok()     { printf "%s[ok]%s    %s\n" "$G" "$X" "$*"; }
section(){ printf "\n%s== %s ==%s\n" "$B" "$*" "$X"; }

# ---- sha256 wrapper (mac uses shasum, linux usually sha256sum) ------------
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
  else
    echo ""
  fi
}

# ---- IOCs -----------------------------------------------------------------
KNOWN_HASH_ROUTER_INIT="ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"
KNOWN_HASH_SETUP_PKGJSON="7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b"
MAL_COMMIT="79ac49eedf774dd4b0cfa308722bc463cfe5885c"
MAL_ACTOR="voicproducoes"

# Compromised TanStack package@version pairs (84 total)
TANSTACK_IOCS="
@tanstack/arktype-adapter@1.166.12
@tanstack/arktype-adapter@1.166.15
@tanstack/eslint-plugin-router@1.161.12
@tanstack/eslint-plugin-router@1.161.9
@tanstack/eslint-plugin-start@0.0.4
@tanstack/eslint-plugin-start@0.0.7
@tanstack/history@1.161.12
@tanstack/history@1.161.9
@tanstack/nitro-v2-vite-plugin@1.154.12
@tanstack/nitro-v2-vite-plugin@1.154.15
@tanstack/react-router-devtools@1.166.16
@tanstack/react-router-devtools@1.166.19
@tanstack/react-router-ssr-query@1.166.15
@tanstack/react-router-ssr-query@1.166.18
@tanstack/react-router@1.169.5
@tanstack/react-router@1.169.8
@tanstack/react-start-client@1.166.51
@tanstack/react-start-client@1.166.54
@tanstack/react-start-rsc@0.0.47
@tanstack/react-start-rsc@0.0.50
@tanstack/react-start-server@1.166.55
@tanstack/react-start-server@1.166.58
@tanstack/react-start@1.167.68
@tanstack/react-start@1.167.71
@tanstack/router-cli@1.166.46
@tanstack/router-cli@1.166.49
@tanstack/router-core@1.169.5
@tanstack/router-core@1.169.8
@tanstack/router-devtools-core@1.167.6
@tanstack/router-devtools-core@1.167.9
@tanstack/router-devtools@1.166.16
@tanstack/router-devtools@1.166.19
@tanstack/router-generator@1.166.45
@tanstack/router-generator@1.166.48
@tanstack/router-plugin@1.167.38
@tanstack/router-plugin@1.167.41
@tanstack/router-ssr-query-core@1.168.3
@tanstack/router-ssr-query-core@1.168.6
@tanstack/router-utils@1.161.11
@tanstack/router-utils@1.161.14
@tanstack/router-vite-plugin@1.166.53
@tanstack/router-vite-plugin@1.166.56
@tanstack/solid-router-devtools@1.166.16
@tanstack/solid-router-devtools@1.166.19
@tanstack/solid-router-ssr-query@1.166.15
@tanstack/solid-router-ssr-query@1.166.18
@tanstack/solid-router@1.169.5
@tanstack/solid-router@1.169.8
@tanstack/solid-start-client@1.166.50
@tanstack/solid-start-client@1.166.53
@tanstack/solid-start-server@1.166.54
@tanstack/solid-start-server@1.166.57
@tanstack/solid-start@1.167.65
@tanstack/solid-start@1.167.68
@tanstack/start-client-core@1.168.5
@tanstack/start-client-core@1.168.8
@tanstack/start-fn-stubs@1.161.12
@tanstack/start-fn-stubs@1.161.9
@tanstack/start-plugin-core@1.169.23
@tanstack/start-plugin-core@1.169.26
@tanstack/start-server-core@1.167.33
@tanstack/start-server-core@1.167.36
@tanstack/start-static-server-functions@1.166.44
@tanstack/start-static-server-functions@1.166.47
@tanstack/start-storage-context@1.166.38
@tanstack/start-storage-context@1.166.41
@tanstack/valibot-adapter@1.166.12
@tanstack/valibot-adapter@1.166.15
@tanstack/virtual-file-routes@1.161.10
@tanstack/virtual-file-routes@1.161.13
@tanstack/vue-router-devtools@1.166.16
@tanstack/vue-router-devtools@1.166.19
@tanstack/vue-router-ssr-query@1.166.15
@tanstack/vue-router-ssr-query@1.166.18
@tanstack/vue-router@1.169.5
@tanstack/vue-router@1.169.8
@tanstack/vue-start-client@1.166.46
@tanstack/vue-start-client@1.166.49
@tanstack/vue-start-server@1.166.50
@tanstack/vue-start-server@1.166.53
@tanstack/vue-start@1.167.61
@tanstack/vue-start@1.167.64
@tanstack/zod-adapter@1.166.12
@tanstack/zod-adapter@1.166.15
"

# Adjacent non-tanstack packages compromised in same campaign
OTHER_IOCS="
@draftauth/core@0.13.1
@draftlab/db@0.16.1
@draftlab/auth-router@0.5.1
safe-action@0.8.3
@taskflow-corp/cli@0.1.25
@taskflow-corp/cli@0.1.24
cmux-agent-mcp@0.1.4
cmux-agent-mcp@0.1.3
@supersurkhet/cli@0.0.3
@supersurkhet/cli@0.0.2
@supersurkhet/sdk@0.0.3
@supersurkhet/sdk@0.0.2
git-branch-selector@1.3.3
git-git-git@1.0.8
@tolka/cli@1.0.2
nextmove-mcp@0.1.3
"

# Files dropped by the worm
WORM_FILES="router_init.js router_runtime.js tanstack_runner.js setup.mjs"

banner
info "Scan root: $ROOT"
info "Started:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ============================================================================
# CHECK 1: known-bad files on disk anywhere under scan root
# ============================================================================
section "1/6  Filesystem scan for worm artifact filenames"

for fn in $WORM_FILES; do
  # -prune node_modules/.cache to avoid noise but keep node_modules itself
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    h="$(sha256 "$f")"
    if [ "$h" = "$KNOWN_HASH_ROUTER_INIT" ]; then
      severe "Known-bad router_init.js hash match: $f"
    elif [ "$fn" = "router_init.js" ] || [ "$fn" = "router_runtime.js" ] || \
         [ "$fn" = "tanstack_runner.js" ]; then
      severe "Worm filename present (verify hash $h): $f"
    else
      hit "Suspicious dropper filename: $f  sha256=$h"
    fi
  done < <(find "$ROOT" -type f -name "$fn" 2>/dev/null)
done

# ============================================================================
# CHECK 2: lockfiles for compromised package@version pairs
# ============================================================================
section "2/6  Lockfile scan for compromised package@version"

LOCKFILES=$(find "$ROOT" \( -name package-lock.json -o -name pnpm-lock.yaml \
                        -o -name yarn.lock -o -name bun.lock \
                        -o -name bun.lockb \) \
            -not -path "*/node_modules/*" 2>/dev/null)

if [ -z "$LOCKFILES" ]; then
  info "No lockfiles under $ROOT (outside node_modules)."
else
  for pv in $TANSTACK_IOCS $OTHER_IOCS; do
    name="${pv%@*}"
    ver="${pv##*@}"
    for lf in $LOCKFILES; do
      found=0
      # npm v1 (top-level): "<name>": { ... "version": "<ver>" ... }
      if awk -v n="\"$name\"" -v v="\"version\": \"$ver\"" '
            index($0,n){ keep=8 }
            keep>0 && index($0,v){ found=1; exit }
            keep>0 { keep-- }
            END { exit !found }
          ' "$lf" 2>/dev/null; then
        severe "$pv resolved in $lf"
        found=1
      fi
      # npm v2/v3 (lockfileVersion 2/3): "node_modules/<name>": { ... "version": "<ver>" ... }
      if [ $found -eq 0 ] && awk -v n="\"node_modules/$name\"" -v v="\"version\": \"$ver\"" '
            index($0,n){ keep=8 }
            keep>0 && index($0,v){ found=1; exit }
            keep>0 { keep-- }
            END { exit !found }
          ' "$lf" 2>/dev/null; then
        severe "$pv resolved in $lf"
        found=1
      fi
      # yarn/pnpm/bun style: name@version or name@npm:version on a single line
      if [ $found -eq 0 ]; then
        if grep -F -q "$name@$ver" "$lf" 2>/dev/null || \
           grep -F -q "${name}@npm:${ver}" "$lf" 2>/dev/null; then
          severe "$pv referenced in $lf"
        fi
      fi
    done
  done
fi

# ============================================================================
# CHECK 3: installed node_modules with malicious versions
# ============================================================================
section "3/6  node_modules package.json version check"

while IFS= read -r pj; do
  [ -z "$pj" ] && continue
  # extract name + version via portable awk
  pname=$(awk -F\" '/"name"[[:space:]]*:/{print $4; exit}' "$pj" 2>/dev/null)
  pver=$(awk -F\"  '/"version"[[:space:]]*:/{print $4; exit}' "$pj" 2>/dev/null)
  [ -z "$pname" ] || [ -z "$pver" ] && continue
  pv="${pname}@${pver}"
  for bad in $TANSTACK_IOCS $OTHER_IOCS; do
    if [ "$pv" = "$bad" ]; then
      severe "Installed: $pv  ($pj)"
    fi
  done
done < <(find "$ROOT" -path "*/node_modules/*/package.json" 2>/dev/null)

# ============================================================================
# CHECK 4: malicious git-dep marker  @tanstack/setup -> github:tanstack/router
# ============================================================================
section "4/6  Malicious @tanstack/setup optionalDependency marker"

while IFS= read -r pj; do
  [ -z "$pj" ] && continue
  if grep -F -q "@tanstack/setup" "$pj" 2>/dev/null; then
    severe "@tanstack/setup dep reference in: $pj"
  fi
  if grep -F -q "$MAL_COMMIT" "$pj" 2>/dev/null; then
    severe "Malicious commit hash $MAL_COMMIT referenced in: $pj"
  fi
done < <(find "$ROOT" -name package.json 2>/dev/null)

# also scan lockfiles for the commit hash
for lf in $LOCKFILES; do
  if grep -F -q "$MAL_COMMIT" "$lf" 2>/dev/null; then
    severe "Malicious commit hash $MAL_COMMIT referenced in: $lf"
  fi
  if grep -F -q "@tanstack/setup" "$lf" 2>/dev/null; then
    severe "@tanstack/setup dep reference in: $lf"
  fi
done

# ============================================================================
# CHECK 5: cred-exfil staging areas + .npmrc with publish token
# ============================================================================
section "5/6  Credential / staging artifact check"

# .npmrc with auth token (the worm reads these)
for rc in "$HOME/.npmrc" "$ROOT/.npmrc"; do
  [ -f "$rc" ] || continue
  if grep -E -q "(_authToken|//registry\.npmjs\.org/:_authToken)" "$rc" 2>/dev/null; then
    hit "npm publish token present in $rc  (rotate if any compromised install ran on this host)"
  fi
done

# .claude/ and .vscode/ injection per StepSecurity guidance
for d in "$HOME/.claude" "$ROOT/.claude" "$HOME/.vscode" "$ROOT/.vscode"; do
  [ -d "$d" ] || continue
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    base=$(basename "$f")
    case "$base" in
      router_runtime.js|setup.mjs|router_init.js|tanstack_runner.js)
        severe "Injected file in $d: $f" ;;
    esac
  done < <(find "$d" -type f 2>/dev/null)
done

# /tmp staging
for f in /tmp/router_init.js /tmp/router_runtime.js /tmp/tanstack_runner.js /tmp/setup.mjs; do
  [ -f "$f" ] && severe "Worm staging file: $f"
done

# Local clones with the malicious actor / worm marker repo names
if command -v git >/dev/null 2>&1; then
  while IFS= read -r gd; do
    [ -z "$gd" ] && continue
    repo_root=$(dirname "$gd")
    if git -C "$repo_root" log --all --format='%an %ae' 2>/dev/null | grep -F -q "$MAL_ACTOR"; then
      severe "Repo with commits by $MAL_ACTOR: $repo_root"
    fi
    if git -C "$repo_root" log --all --format='%H' 2>/dev/null | grep -F -q "$MAL_COMMIT"; then
      severe "Repo contains malicious commit $MAL_COMMIT: $repo_root"
    fi
  done < <(find "$ROOT" -maxdepth 4 -type d -name ".git" 2>/dev/null)
fi

# ============================================================================
# CHECK 6: GitHub Actions workflow tampering
# ============================================================================
section "6/6  GitHub Actions workflow tampering"

while IFS= read -r wf; do
  [ -z "$wf" ] && continue
  if grep -E -q "(shai-hulud|tanstack_runner|router_runtime|setup\.mjs)" "$wf" 2>/dev/null; then
    severe "Suspicious workflow content: $wf"
  fi
done < <(find "$ROOT" -path "*.github/workflows/*" \( -name "*.yml" -o -name "*.yaml" \) 2>/dev/null)

# ============================================================================
# SUMMARY
# ============================================================================
section "Summary"
info "Finished:  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
info "Findings:  $HITS  (severe: $SEVERE)"

if [ "$SEVERE" -gt 0 ]; then
  printf "\n%s[!] TRUE POSITIVE LIKELY%s\n" "$R$B" "$X"
  cat <<'EOF'

    ============================================================
    READ THIS BEFORE TOUCHING TOKENS
    ============================================================
    This worm family carries a dead-man wiper. If it loses BOTH
    npm and GitHub exfil/propagation channels while still resident,
    it can detonate:
        find ~ -type f -writable -user $USER -print0 \
          | xargs -0 shred -uvz -n 1
    Rotating tokens FIRST on a still-infected host is what trips it.
    Containment comes before rotation. Follow the order below.

    ------------------------------------------------------------
    PHASE 1  -  CONTAIN  (do these before anything else)
    ------------------------------------------------------------
    1. Network-isolate the host from npmjs.org, github.com, and the
       Session network (lokinet, oxen) at the egress firewall.
       Do NOT just `ifconfig down` from the host - shell history /
       sudo / running daemons may trigger the worm.
    2. Stop background runners that could re-execute the payload:
         - launchctl unload any com.* LaunchAgents added today (mac)
         - systemctl --user stop / disable suspicious units (linux)
         - kill any node/bun processes whose argv contains
           router_init / router_runtime / tanstack_runner / setup.mjs
       Do this from a fresh shell so .bashrc/.zshrc hooks don't fire.
    3. Snapshot the box (full disk image / EBS snapshot / Time Machine).
       Wiper-resistant forensic copy BEFORE you change anything.
    4. Delete the worm artifacts identified above. Do NOT `rm -rf
       node_modules && npm reinstall` yet - reinstall pulls the same
       poisoned lockfile entries back. Pin clean versions in
       package.json + delete the lockfile first.

    ------------------------------------------------------------
    PHASE 2  -  KILL CI/CD PERSISTENCE  (still no token rotation)
    ------------------------------------------------------------
    5. In every affected GitHub org, BEFORE rotating any creds:
         a. Delete unrecognised self-hosted runners (org + repo level).
         b. Remove unrecognised GitHub Actions workflows, especially
            files referencing shai-hulud, tanstack_runner, setup.mjs,
            discussion.yaml, or scheduled cron triggers added today.
         c. Disable Actions on the repo while you triage.
         d. Revoke GitHub Actions OIDC federation grants to npm for
            every affected repo. (Done at npmjs.com -> trusted
            publishers, NOT in GitHub.) This stops the worm from
            republishing even if it still has the OIDC token.
    6. In npm: revoke (do not rotate) any granular automation tokens
       associated with affected packages. Unpublish or deprecate any
       suspect versions you control.

    ------------------------------------------------------------
    PHASE 3  -  ROTATE  (only after Phases 1-2 are done)
    ------------------------------------------------------------
    7. Rotate from the most-blast-radius outward:
         AWS instance roles + static keys -> Vault tokens ->
         k8s SA tokens -> NX_CLOUD_ACCESS_TOKEN -> cloud provider
         creds in CI secrets -> GitHub PATs -> npm tokens last.
       Reason: npm/GitHub token rotation is what trips the wiper.
       By the time you rotate those, the host should be offline /
       wiped / rebuilt anyway.
    8. Rebuild affected developer workstations from a known-good
       image. Do not "clean" them - the payload is 2.3 MB obfuscated
       JS with persistence hooks; you will miss something.

    ------------------------------------------------------------
    PHASE 4  -  HUNT  (assume lateral movement)
    ------------------------------------------------------------
    9. Pull GitHub audit log for the org for the window
       2026-05-11T19:20Z -> now. Look for:
         - repo creations with random Dune-flavored names
         - repos with description "A Mini Shai-Hulud has Appeared"
           (marker repos: siridar-ghola-567, tleilaxu-ornithopter-43)
         - branches named shai-hulud or PRs adding workflows
         - new SSH keys / deploy keys / PATs created
         - workflows referencing discussion.yaml (related Shai-Hulud
           2.0 family backdoor; not confirmed in this TanStack
           variant but worth checking)
   10. Hunt outbound from build hosts since 2026-05-11 for traffic
       to Session / Oxen / Lokinet infrastructure. The TanStack
       worm embeds the full Session signalservice Protocol Buffers
       schema and uses Session for credential exfil. No fixed
       port/IP set is published; flag any unexpected egress from
       CI runners and dev workstations to non-corporate domains.
   11. Pull Wazuh / SIEM for any host where this script reported
       severe. Treat as confirmed incident, open IR ticket.
EOF
  exit 2
elif [ "$HITS" -gt 0 ]; then
  printf "\n%s[~] Suspicious indicators present, verify manually.%s\n" "$Y" "$X"
  exit 1
else
  printf "\n%s[ok] No Shai-Hulud TanStack IOCs detected under %s%s\n" "$G" "$ROOT" "$X"
  exit 0
fi
