#!/bin/sh
# Fake docker for s3-preflight P3 (tests/infra/image.rs): no daemon, no
# image. Copied into a temp bin dir as `docker`.
#   docker version --format ...   prints FAKE_DOCKER_VERSION ("<version>
#                                 <arch>"); unset: the daemon is down (exit 1)
#   docker run ... df -Pk /       a `df -Pk` table whose Available column is
#                                 FAKE_DOCKER_FREE_KB (unset: the run fails)
#   docker image inspect [-f FORMAT] IMAGE
#                                 S11 (admission's preconditions): with
#                                 FAKE_DOCKER_IMAGE_ID set, the image exists
#                                 (exit 0; with -f or --format that id is
#                                 printed, else a one-object JSON array);
#                                 unset, "Error: No such image: IMAGE", exit 1
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
  image)
    test "${2:-}" = inspect || { echo "fake docker: unsupported: $*" >&2; exit 2; }
    shift 2
    format=
    image=
    while [ $# -gt 0 ]; do
      case "$1" in
        -f|--format) shift; format=${1:-} ;;
        --format=*) format=${1#--format=} ;;
        -*) echo "fake docker: unsupported: image inspect $1" >&2; exit 2 ;;
        *) image=$1 ;;
      esac
      shift
    done
    test -n "$image" || { echo "fake docker: image inspect needs an image" >&2; exit 2; }
    if [ -z "${FAKE_DOCKER_IMAGE_ID:-}" ]; then
      echo "Error: No such image: $image" >&2
      exit 1
    fi
    if [ -n "$format" ]; then
      echo "$FAKE_DOCKER_IMAGE_ID"
    else
      printf '[{"Id":"%s","RepoTags":["%s"]}]\n' "$FAKE_DOCKER_IMAGE_ID" "$image"
    fi ;;
  run)
    test -n "${FAKE_DOCKER_FREE_KB:-}" || { echo "docker: fake run failure" >&2; exit 125; }
    printf 'Filesystem     1024-blocks     Used Available Capacity Mounted on\n'
    printf 'overlay           61202244 11077240 %s      19%% /\n' "$FAKE_DOCKER_FREE_KB" ;;
  *)
    echo "fake docker: unsupported: $*" >&2
    exit 2 ;;
esac
