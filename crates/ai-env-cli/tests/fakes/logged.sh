#!/bin/sh
# A tool that must not run (tests/infra/image.rs): copied into a temp bin dir
# under each name a recipe could call (aws, pulumi, docker, curl, gpg, cargo,
# node, ...). It appends "<name> <argv>" to FAKE_LOG and fails with exit 1, so
# `make -n` proves a dry parse by an empty log, and a real recipe run sees a
# tool that is present but does nothing.
if [ -n "${FAKE_LOG:-}" ]; then
  printf '%s %s\n' "$(basename "$0")" "$*" >> "$FAKE_LOG"
fi
exit 1
