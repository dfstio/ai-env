#!/bin/sh
# Fake docker for s3-preflight P3 (tests/infra/image.rs): no daemon, no
# image. Copied into a temp bin dir as `docker`.
#   docker version --format ...   prints FAKE_DOCKER_VERSION ("<version>
#                                 <arch>"); unset: the daemon is down (exit 1)
#   docker run ... df -Pk /       a `df -Pk` table whose Available column is
#                                 FAKE_DOCKER_FREE_KB (unset: the run fails)
# Environment:
#   FAKE_DOCKER_LOG   when set, each call's argv is appended here, one line
set -u
if [ -n "${FAKE_DOCKER_LOG:-}" ]; then
  printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"
fi
case "${1:-}" in
  version)
    if [ -z "${FAKE_DOCKER_VERSION:-}" ]; then
      echo "Cannot connect to the Docker daemon (fake)" >&2
      exit 1
    fi
    echo "$FAKE_DOCKER_VERSION" ;;
  run)
    test -n "${FAKE_DOCKER_FREE_KB:-}" || { echo "docker: fake run failure" >&2; exit 125; }
    printf 'Filesystem     1024-blocks     Used Available Capacity Mounted on\n'
    printf 'overlay           61202244 11077240 %s      19%% /\n' "$FAKE_DOCKER_FREE_KB" ;;
  *)
    echo "fake docker: unsupported: $*" >&2
    exit 2 ;;
esac
