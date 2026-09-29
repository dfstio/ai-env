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

# Packages the agent needs (git, archives, ps, useradd, find); no weak deps,
# so no systemd. No chrony and no nftables in v0 (the shim measures the clock).
RUN microdnf -y --setopt=install_weak_deps=0 install tar gzip unzip git-core procps-ng shadow-utils findutils \
 && microdnf clean all \
 && rm -rf /var/cache/dnf /var/cache/yum /var/lib/dnf/history* /var/log/dnf* /var/log/hawkey.log \
 && rm -f /etc/machine-id /var/lib/systemd/random-seed

# The agent user mirrors the Mac: uid/gid 1000, HOME /Users/mike.
RUN mkdir -p /Users /etc/claude-code /etc/ai-env \
 && groupadd --gid 1000 mike \
 && useradd --uid 1000 --gid 1000 --home-dir /Users/mike --create-home --shell /bin/bash mike \
 && chmod 0700 /Users/mike

# Claude Code, pinned by version, size and SHA-256 (image/claude.lock, written
# by `make claude-pin`). HTTPS only; the gate runs --version with a cleared
# environment and a throwaway HOME, then removes every trace of it.
COPY claude.lock /etc/ai-env/claude.lock
RUN set -eu; \
    chmod 0644 /etc/ai-env/claude.lock; \
    . /etc/ai-env/claude.lock; \
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o /usr/local/bin/claude \
      "https://downloads.claude.ai/claude-code-releases/${CLAUDE_VERSION}/${CLAUDE_PLATFORM}/claude"; \
    size=$(stat -c %s /usr/local/bin/claude); \
    test "$size" = "$CLAUDE_SIZE" || { echo "claude: size $size, the lock pins $CLAUDE_SIZE"; exit 1; }; \
    echo "${CLAUDE_SHA256}  /usr/local/bin/claude" | sha256sum --check --strict; \
    chmod 0755 /usr/local/bin/claude; \
    gate=$(mktemp -d); \
    out=$(env -i HOME="$gate" PATH=/usr/local/bin:/usr/bin:/bin timeout 30 /usr/local/bin/claude --version); \
    rm -rf "$gate" /root/.claude /root/.claude.json /root/.cache /root/.config; \
    test "$out" = "${CLAUDE_VERSION} (Claude Code)" || { echo "claude --version printed: $out"; exit 1; }; \
    echo "claude version gate: $out"

# Managed settings (root, 0644: read by claude regardless of --setting-sources)
# and the reviewed config subset. .claude.json goes to both places claude
# looks (CLAUDE_CONFIG_DIR set and unset); never a legacy .config.json.
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
    git config --system push.default nothing

# The shim last: it changes most often.
COPY ai-env /usr/local/bin/ai-env
RUN chmod 0755 /usr/local/bin/ai-env && /usr/local/bin/ai-env --version

EXPOSE 8080 9000 9418
ENTRYPOINT ["/usr/local/bin/ai-env","shim","--app-port","8080","--hooks-port","9000","--code-port","9418","--claude","/usr/local/bin/claude","--home","/Users/mike","--uid","1000"]
