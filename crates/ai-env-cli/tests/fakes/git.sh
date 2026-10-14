#!/bin/sh
# Fake `git` for the S8 workspace tests: a logging passthrough to the real
# git, never a git of its own. POSIX sh; runs under macOS /bin/sh (bash 3.2
# in sh mode). Hard-linked from a cached master (tests/common/mod.rs,
# `install_fake_git`) as the Mac's `git` first on PATH, the git a test hands
# `GitRun::with_program`, and the shim's `--git` (tests/common/remote.rs);
# never written over in place (the link shares the master's inode). It
# reaches no network itself: the code under test gives the real git local
# paths only.
#
# Each call appends one line to GIT_ARGV_LOG, its fields separated by tabs:
#   env=<the GIT_* names set when it started, sorted, comma-separated; - for none>
#   fds=<the descriptors 3 to 254 open when it started, comma-separated; - for none>
#   then every argument, with % tab and newline written as %25 %09 %0A
# Names only, never a value. Both are read before the knobs file below, so
# they are what the caller passed: `GitRun::mac` strips every inherited
# GIT_*, `GitRun::vm` starts from an empty environment, and no credential
# descriptor may reach a git (S8 phase 4).
#
# Knobs:
#   GIT_REAL            the real git, an absolute path (required; the harness
#                       resolves it once)
#   GIT_ARGV_LOG        the log above (unset: nothing is logged)
#   FAKE_GIT_FAIL       <subcommand>: that subcommand (the first argument that
#                       is not a global option) is logged, prints
#                       "fatal: fake git: <subcommand> failed (FAKE_GIT_FAIL)"
#                       on stderr and exits 128, as a failing git does
#   FAKE_GIT_KEEP_PACK  <dir>: a copy of every pack index-pack is given (its
#                       pack-file argument, or stdin with --stdin) and of every
#                       pack pack-objects writes (stdout with --stdout, else
#                       <base-name>-<hash>.pack) lands there as
#                       <subcommand>-<pid>.pack; such a call buffers the pack
#                       whole before it goes on
#
# The caller's environment cannot carry the knobs (GitRun strips GIT_* on the
# Mac and clears it in the VM), so when a file `<this path>.knobs` sits beside
# the link the caller ran (single-quoted export lines, written by the
# harness), it is sourced after the names and descriptors above were taken.

# The descriptors open at the start, from 3 to 254 (macOS /bin/sh keeps this
# script on 255).
fds=""
n=3
while [ "$n" -le 254 ]; do
  if [ -e "/dev/fd/$n" ]; then
    fds="$fds${fds:+,}$n"
  fi
  n=$((n + 1))
done
names=$(env | sed -n 's/^\(GIT_[A-Za-z0-9_]*\)=.*/\1/p' | sort -u | tr '\n' ',' | sed 's/,$//')

case $0 in
  */*)
    if [ -f "$0.knobs" ]; then
      . "$0.knobs"
    fi
    ;;
esac

# The subcommand: the first argument past git's global options (those that
# take a value as the next argument skip it), and its position.
sub=""
subpos=0
skip=0
for a in "$@"; do
  subpos=$((subpos + 1))
  if [ "$skip" = "1" ]; then
    skip=0
    continue
  fi
  case "$a" in
    -c|-C|--git-dir|--work-tree|--namespace|--super-prefix|--config-env) skip=1 ;;
    -*) : ;;
    *) sub=$a; break ;;
  esac
done

if [ -n "${GIT_ARGV_LOG:-}" ]; then
  awk -v env="${names:--}" -v fds="${fds:--}" 'BEGIN {
    line = "env=" env "\tfds=" fds
    for (i = 1; i < ARGC; i++) {
      a = ARGV[i]
      gsub(/%/, "%25", a)
      gsub(/\t/, "%09", a)
      gsub(/\n/, "%0A", a)
      line = line "\t" a
    }
    print line
    exit
  }' "$@" >> "$GIT_ARGV_LOG"
fi

if [ -n "${FAKE_GIT_FAIL:-}" ] && [ "$sub" = "$FAKE_GIT_FAIL" ]; then
  printf 'fatal: fake git: %s failed (FAKE_GIT_FAIL)\n' "$sub" >&2
  exit 128
fi

case "${GIT_REAL:-}" in
  /*) : ;;
  *)
    printf 'fatal: fake git: GIT_REAL is not an absolute path (%s)\n' "${GIT_REAL:-unset}" >&2
    exit 128
    ;;
esac

# The last argument after the subcommand that is not an option (`-o` skips
# its value): index-pack's pack file, pack-objects' base name.
operand() {
  shift "$subpos"
  skip=0
  last=""
  for a in "$@"; do
    if [ "$skip" = "1" ]; then
      skip=0
      continue
    fi
    case "$a" in
      -o) skip=1 ;;
      -*) : ;;
      *) last=$a ;;
    esac
  done
  printf '%s' "$last"
}

if [ -n "${FAKE_GIT_KEEP_PACK:-}" ]; then
  kept="$FAKE_GIT_KEEP_PACK/$sub-$$.pack"
  case "$sub" in
    index-pack)
      stdin=0
      for a in "$@"; do
        if [ "$a" = "--stdin" ]; then
          stdin=1
        fi
      done
      mkdir -p "$FAKE_GIT_KEEP_PACK"
      if [ "$stdin" = "1" ]; then
        cat > "$kept"
        exec "$GIT_REAL" "$@" < "$kept"
      fi
      pack=$(operand "$@")
      if [ -n "$pack" ] && [ -f "$pack" ]; then
        cp "$pack" "$kept"
      fi
      ;;
    pack-objects)
      tostdout=0
      for a in "$@"; do
        if [ "$a" = "--stdout" ]; then
          tostdout=1
        fi
      done
      mkdir -p "$FAKE_GIT_KEEP_PACK"
      if [ "$tostdout" = "1" ]; then
        "$GIT_REAL" "$@" > "$kept"
        rc=$?
        cat "$kept"
        exit "$rc"
      fi
      base=$(operand "$@")
      out=$("$GIT_REAL" "$@")
      rc=$?
      if [ -n "$out" ]; then
        printf '%s\n' "$out"
      fi
      for h in $out; do
        if [ -f "$base-$h.pack" ]; then
          cp "$base-$h.pack" "$kept"
        fi
      done
      exit "$rc"
      ;;
  esac
fi

exec "$GIT_REAL" "$@"
