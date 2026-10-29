# ai-env MicroVM agent image (S3 v0). AWS Lambda MicroVMs builds it from the
# zip `make image-zip` stages: exactly the files image/MANIFEST lists plus the
# cross-built shim (image/ai-env). The platform starts the ENTRYPOINT, waits
# for POST /ready on port 9000, snapshots disk and memory, and calls
# /validate on a fresh VM from that snapshot. Everything here is therefore
# shared by every VM: no secret, no per-machine id, no build-time state.

# The base container, pinned by digest (the Makefile's BASE_IMAGE and gate G3
# read this line). Fallback if the builder rejects a digest: the dated tag
# public.ecr.aws/lambda/microvms:al2023-minimal.2026.07.01.14
FROM public.ecr.aws/lambda/microvms:al2023-minimal@sha256:05cb9b38d841e7ff1b693dc9e894909612f340bf99ec97d426e8000a5bbe96c3

# Packages the agent needs (git, archives, ps, useradd, find; dig for the S5
# egress check and dns-path probe); no weak deps, so no systemd. No chrony
# and no nftables: the shim measures the clock, and the hooks are guarded by
# socket ownership (`--hook-source peer`, S6), not by a firewall.
RUN microdnf -y --setopt=install_weak_deps=0 install tar gzip unzip git-core procps-ng shadow-utils findutils bind-utils \
 && microdnf clean all \
 && rm -rf /var/cache/dnf /var/cache/yum /var/lib/dnf/history* /var/log/dnf* /var/log/hawkey.log \
 && rm -f /etc/machine-id /var/lib/systemd/random-seed

# Git smart-HTTP (S9): the shim's helper runs `git http-backend` as the agent,
# upload-pack only. The gate: git-core ships it, and on a throwaway bare
# repository it answers protocol v2's advertisement, no error status, with
# the helper's command-line overrides and a CGI environment of its kind.
RUN set -eu; \
    test -x "$(git --exec-path)/git-http-backend" || { echo "git-http-backend is missing from $(git --exec-path)"; exit 1; }; \
    repo=$(mktemp -d); \
    git -c init.defaultBranch=main init -q --bare "$repo"; \
    out=$(env -i HOME="$repo" PATH=/usr/bin:/bin LC_ALL=C GIT_CONFIG_GLOBAL=/dev/null GIT_PROJECT_ROOT="$repo" GIT_HTTP_EXPORT_ALL=1 PATH_INFO=/info/refs REQUEST_METHOD=GET QUERY_STRING=service=git-upload-pack HTTP_GIT_PROTOCOL=version=2 REMOTE_ADDR=127.0.0.1 \
      git -c http.receivepack=false -c http.getanyfile=false -c http.uploadpack=true http-backend); \
    rm -rf "$repo"; \
    case "$out" in *Status:*) echo "http-backend answered an error: $out"; exit 1 ;; esac; \
    case "$out" in *"Content-Type: application/x-git-upload-pack-advertisement"*) ;; *) echo "http-backend answered no advertisement: $out"; exit 1 ;; esac; \
    case "$out" in *"version 2"*) ;; *) echo "http-backend answered no protocol v2: $out"; exit 1 ;; esac; \
    echo "http-backend gate: $(git --version), protocol v2"

# The agent user mirrors the Mac: uid/gid 1000, HOME /Users/mike.
RUN mkdir -p /Users /etc/claude-code /etc/ai-env \
 && groupadd --gid 1000 mike \
 && useradd --uid 1000 --gid 1000 --home-dir /Users/mike --create-home --shell /bin/bash mike \
 && chmod 0700 /Users/mike

# S9's transcript store: curl moves its bytes as ai-env-net (uid/gid 999, no
# login, no home), started by the root shim with the presigned URL on fd 3,
# a descriptor the agent (uid 1000) cannot read. A group the packages above
# made at gid 999 (openssh's ssh_keys, a dynamic system group) first moves to
# the highest free system gid below it, its files with it (their modes kept:
# a chgrp clears setgid), so 999 is ai-env-net's alone. The gate: curl speaks
# https, decodes gzip (libz: S11's compressed stage) and is 7.84 or later (the
# shim's write-out reads headers with %header{}).
RUN set -eu; \
    if held=$(getent group 999); then \
      name=${held%%:*}; gid=998; \
      while getent group "$gid" >/dev/null; do gid=$((gid - 1)); done; \
      groupmod --gid "$gid" "$name"; \
      find / -xdev -gid 999 -print | while IFS= read -r f; do mode=$(stat -c %a "$f"); chgrp -h "$gid" "$f"; [ -L "$f" ] || chmod "$mode" "$f"; done; \
      echo "gid 999 was $name's: now $gid"; \
    fi; \
    if held=$(getent passwd 999); then echo "uid 999 is ${held%%:*}'s already"; exit 1; fi; \
    groupadd --system --gid 999 ai-env-net; \
    useradd --system --uid 999 --gid 999 --no-create-home --home-dir / --shell /sbin/nologin ai-env-net; \
    test "$(id -u ai-env-net):$(id -g ai-env-net)" = 999:999; \
    protocols=$(curl --version | while IFS= read -r line; do case $line in (Protocols:*) echo "${line#Protocols:}";; esac; done); \
    case " $protocols " in *" https "*) ;; *) echo "curl lists no https:$protocols"; exit 1;; esac; \
    set -- $(curl --version | head -n 1); \
    major=${2%%.*}; minor=${2#*.}; minor=${minor%%.*}; \
    { [ "$major" -gt 7 ] || { [ "$major" -eq 7 ] && [ "$minor" -ge 84 ]; }; } || { echo "curl $2: the transcript transfers need 7.84 or later"; exit 1; }; \
    features=$(curl --version | while IFS= read -r line; do case $line in (Features:*) echo "${line#Features:}";; esac; done); \
    case " $features " in *" libz "*) ;; *) echo "curl lists no libz:$features (a gzip-staged transcript is pulled with curl's compressed)"; exit 1;; esac; \
    echo "ai-env-net 999:999; curl $2 with https and libz"

# Claude Code, pinned by version, size and SHA-256 (image/claude.lock, written
# by `make claude-pin`). HTTPS only; the gate runs --version with a cleared
# environment and a throwaway HOME, then removes every trace of it. Right
# after the hash, S10's strings gate: the binary holds every text the moved
# chat relies on (the cut's flag and its miss, a fresh chat's flag and its
# refusal); a missing one fails the build naming it.
COPY claude.lock /etc/ai-env/claude.lock
RUN set -eu; \
    chmod 0644 /etc/ai-env/claude.lock; \
    . /etc/ai-env/claude.lock; \
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o /usr/local/bin/claude \
      "https://downloads.claude.ai/claude-code-releases/${CLAUDE_VERSION}/${CLAUDE_PLATFORM}/claude"; \
    size=$(stat -c %s /usr/local/bin/claude); \
    test "$size" = "$CLAUDE_SIZE" || { echo "claude: size $size, the lock pins $CLAUDE_SIZE"; exit 1; }; \
    echo "${CLAUDE_SHA256}  /usr/local/bin/claude" | sha256sum --check --strict; \
    for want in '--resume-session-at' 'No message found with message.uuid of:' '--session-id' 'is already in use'; do \
      LC_ALL=C grep -qaF -e "$want" /usr/local/bin/claude || { echo "claude ${CLAUDE_VERSION} lacks the string S10 relies on: $want"; exit 1; }; \
    done; \
    echo "claude strings gate: the cut's and the fresh chat's four strings"; \
    chmod 0755 /usr/local/bin/claude; \
    gate=$(mktemp -d); \
    out=$(env -i HOME="$gate" PATH=/usr/local/bin:/usr/bin:/bin timeout 30 /usr/local/bin/claude --version); \
    rm -rf "$gate" /root/.claude /root/.claude.json /root/.cache /root/.config; \
    test "$out" = "${CLAUDE_VERSION} (Claude Code)" || { echo "claude --version printed: $out"; exit 1; }; \
    echo "claude version gate: $out"

# Managed settings (root, 0644: read by claude regardless of --setting-sources)
# and the reviewed config subset. .claude.json goes to both places claude
# looks (CLAUDE_CONFIG_DIR set and unset); never a legacy .config.json. The
# system git config: no automatic maintenance (an agent's commit would start
# a background gc --auto whose prune-packed can meet a helper's object write).
COPY managed-settings.json /etc/claude-code/managed-settings.json
COPY claude/ /Users/mike/.claude/
RUN set -eu; \
    cp /Users/mike/.claude/claude.json /Users/mike/.claude/.claude.json; \
    mv /Users/mike/.claude/claude.json /Users/mike/.claude.json; \
    chmod 0644 /etc/claude-code/managed-settings.json /Users/mike/.claude/settings.json /Users/mike/.claude/CLAUDE.md; \
    chmod 0600 /Users/mike/.claude/.claude.json /Users/mike/.claude.json; \
    chmod 0755 /Users/mike/.claude/agents /Users/mike/.claude/skills /Users/mike/.claude/commands; \
    chmod 0700 /Users/mike/.claude; \
    chown -R 1000:1000 /Users/mike; \
    git config --system init.defaultBranch main; \
    git config --system user.name claude-agent; \
    git config --system user.email claude-agent@ai-env.invalid; \
    git config --system push.default nothing; \
    git config --system maintenance.auto false

# The shim last: it changes most often. Then S10's seed-record gate: the
# shim keeps the VM's last seed's record in /var/lib/ai-env/seed-record.json
# (root's, 0600) so a shim restart keeps it; the directory is root's, 0700,
# and empty in the image, which every VM shares: a record baked in would be
# every VM's.
COPY ai-env /usr/local/bin/ai-env
RUN chmod 0755 /usr/local/bin/ai-env && /usr/local/bin/ai-env --version
RUN set -eu; \
    install -d -m 0700 -o 0 -g 0 /var/lib/ai-env; \
    test "$(stat -c '%u:%g %a' /var/lib/ai-env)" = "0:0 700" || { echo "/var/lib/ai-env is $(stat -c '%u:%g %a' /var/lib/ai-env), not root's 0700"; exit 1; }; \
    test -z "$(find /var/lib/ai-env -mindepth 1 -print -quit)" || { echo "a seed record is baked into the image: $(ls -A /var/lib/ai-env)"; exit 1; }; \
    echo "seed-record gate: /var/lib/ai-env root 0700, empty"

# S11's claude-cache gate: the shim fetches staged claudes into
# /opt/ai-env/claude/<sha256>/claude (root's: the directories 0755, the files
# 0555) and keeps their index in /var/lib/ai-env, which the seed-record gate
# keeps empty. The cache is root's, 0755 and empty in the image, which every
# VM shares: a claude baked in would be every VM's.
RUN set -eu; \
    install -d -m 0755 -o 0 -g 0 /opt/ai-env /opt/ai-env/claude; \
    test "$(stat -c '%u:%g %a' /opt/ai-env/claude)" = "0:0 755" || { echo "/opt/ai-env/claude is $(stat -c '%u:%g %a' /opt/ai-env/claude), not root's 0755"; exit 1; }; \
    test -z "$(find /opt/ai-env/claude -mindepth 1 -print -quit)" || { echo "a claude is baked into the cache: $(ls -A /opt/ai-env/claude)"; exit 1; }; \
    echo "claude-cache gate: /opt/ai-env/claude root 0755, empty"

# S13's VM side of the relay: ai-env-relay-client runs as ai-env-net (999),
# one per claude spawn the Mac gave a relay session, started by the root shim
# with that session on fd 3 alone; it serves /run/ai-env/relay/<leader>.sock
# to that spawn's processes and dials the relay's private face over TLS 1.3.
# ai-env-relay-mcp is the stdio MCP server claude starts from the baked
# /etc/ai-env/relay-mcp.json (the shim adds --mcp-config=<it>). The gate:
# both print `<name> <the shim's version>` and are root's, 0755; the config
# is root's, 0644, and names that server alone; /run/ai-env is absent (the
# shim makes it).
COPY ai-env-relay-client ai-env-relay-mcp /usr/local/bin/
COPY relay-mcp.json /etc/ai-env/relay-mcp.json
RUN set -eu; \
    chmod 0755 /usr/local/bin/ai-env-relay-client /usr/local/bin/ai-env-relay-mcp; \
    chmod 0644 /etc/ai-env/relay-mcp.json; \
    shim=$(/usr/local/bin/ai-env --version); shim=${shim##* }; \
    for b in ai-env-relay-client ai-env-relay-mcp; do \
      v=$("/usr/local/bin/$b" --version); \
      test "$v" = "$b $shim" || { echo "$b --version printed $v, not $b $shim"; exit 1; }; \
      test "$(stat -c '%u:%g %a' "/usr/local/bin/$b")" = "0:0 755" || { echo "/usr/local/bin/$b is $(stat -c '%u:%g %a' "/usr/local/bin/$b")"; exit 1; }; \
    done; \
    test "$(stat -c '%u:%g %a' /etc/ai-env/relay-mcp.json)" = "0:0 644" || { echo "/etc/ai-env/relay-mcp.json is $(stat -c '%u:%g %a' /etc/ai-env/relay-mcp.json)"; exit 1; }; \
    grep -qF '"command":"/usr/local/bin/ai-env-relay-mcp"' /etc/ai-env/relay-mcp.json || { echo "/etc/ai-env/relay-mcp.json names another program"; exit 1; }; \
    test ! -e /run/ai-env || { echo "/run/ai-env is baked into the image: $(ls -A /run/ai-env)"; exit 1; }; \
    echo "relay gate: ai-env-relay-client and ai-env-relay-mcp $shim, root 0755; relay-mcp.json root 0644; no /run/ai-env"

EXPOSE 8080 9000 9418
ENTRYPOINT ["/usr/local/bin/ai-env","shim","--app-port","8080","--hooks-port","9000","--code-port","9418","--claude","/usr/local/bin/claude","--home","/Users/mike","--uid","1000","--hook-source","peer"]
