#!/bin/sh
# Fake `curl` for S9's transcript transfers in the VM (shim::s3xfer): the
# root shim runs curl as `-q -K /dev/fd/3`, its whole configuration (the
# presigned URL among it) on descriptor 3 and nothing secret in its argv or
# environment (plans/s9-contracts.md §3.4). POSIX sh; runs under macOS
# /bin/sh (bash 3.2 in sh mode). Hard-linked from a cached master
# (tests/common/curl.rs, `install_fake_curl`) as the shim's `--curl`; never
# written over in place. It reaches no network itself unless S3CURL_REAL
# names a real curl (then the tests' loopback fake S3 is behind it).
#
# argv must be exactly `-q -K /dev/fd/3` (else exit 2, "fake curl: unexpected
# argv"); `--version` alone prints a curl 8.11.1 line listing https.
#
# Each call appends one line to S3CURL_LOG, its fields separated by tabs:
#   uid=<id -u>
#   fds=<the descriptors 3 to 254 open when it started, comma-separated; - for none>
#   config=<descriptor 3's bytes, with % tab and newline written %25 %09 %0A>
#   then every argument, escaped the same way
# and `<S3CURL_LOG>.count` numbers the calls from 1 (`<n>` below); the
# configuration is also kept as `<S3CURL_LOG>.<n>.config`.
#
# Knobs, read from `<this path>.knobs` only (every inherited S3CURL_* is
# unset first; the shim clears curl's environment anyway):
#   S3CURL_LOG       the log above (unset: nothing is logged)
#   S3CURL_REAL      a real curl: the call is logged, then that curl runs
#                    `-q -K /dev/fd/3` with the kept configuration on fd 3
#   S3CURL_REAL_ONLY S11: with S3CURL_REAL, a method (`PUT`): only a call
#                    whose configuration says `request = "<it>"` runs the
#                    real curl; any other is played as without S3CURL_REAL
#                    (a claude relay's release GET from S3CURL_BODY, never
#                    the network; its PUT to the tests' S3)
#   Without S3CURL_REAL the fake plays S3:
#   S3CURL_FAIL      <n>: exit n after logging, with no status line
#   S3CURL_SLOW_MS   ms to sleep first
#   S3CURL_SAVE      <dir>: a PUT's body (stdin, read to its end) is kept as <dir>/<n>.put
#   S3CURL_BODIES    <dir>: a GET writes <dir>/<n> when present,
#   S3CURL_BODY      else this file (else nothing)
#   S3CURL_ENCODING  S11: gzip (else unset): the GET bodies above are gzip
#                    streams stored with Content-Encoding: gzip; a
#                    configuration holding a `compressed` line writes them
#                    decoded (/usr/bin/gzip -dc), one without as stored, as
#                    curl does. Unset: bodies are served as they are, with or
#                    without `compressed`. With S3CURL_REAL the real curl
#                    behind it decodes by the fake S3's header.
#   S3CURL_STATUS    the HTTP status reported (default 200); 400 or more also
#                    writes <Error><Code><S3CURL_CODE or AccessDenied></Code></Error>
#                    to stdout (not for a GET whose configuration says `fail`)
#   S3CURL_VERSION   the version id reported (default fake-version-<n>)
# then stderr gets the configuration's write-out line:
#   ai-env-curl status=<status> version=<version> checksum=<the config's
#   x-amz-checksum-sha256 value, or empty> etag="fake-<n>"
# and ` redirects=0` after it when the write-out names %{num_redirects} (S11:
# the claude relay's release GET, LD-19).
# S11: a configuration's `max-filesize = N` is honoured as curl does with S3's
# (or the release's) Content-Length: a GET body whose stored size (the bytes
# served, before any gzip decode) is over N is refused before the transfer:
# nothing on stdout, stderr gets `curl: (63) Maximum file size exceeded` before
# the write-out line (still status=<status>), and the exit is 63. A body of N
# bytes or fewer is served whole.

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

for v in $(env | sed -n 's/^\(S3CURL_[A-Za-z0-9_]*\)=.*/\1/p'); do
  unset "$v"
done
case $0 in
  */*)
    if [ -f "$0.knobs" ]; then
      . "$0.knobs"
    fi
    ;;
esac

if [ "$#" -eq 1 ] && [ "$1" = "--version" ]; then
  echo "curl 8.11.1 (aarch64-unknown-linux-gnu) libcurl/8.11.1 OpenSSL/3.2.2 zlib/1.3.1 nghttp2/1.64.0"
  echo "Release-Date: 2024-12-11"
  echo "Protocols: file ftp ftps http https"
  echo "Features: alt-svc AsynchDNS HSTS HTTP2 HTTPS-proxy IPv6 Largefile libz SSL threadsafe UnixSockets"
  exit 0
fi
if [ "$#" -ne 3 ] || [ "$1" != "-q" ] || [ "$2" != "-K" ] || [ "$3" != "/dev/fd/3" ]; then
  echo "fake curl: unexpected argv" >&2
  exit 2
fi

# `<n>`, the configuration kept, and the log line, under one lock (calls may run side by side).
count=0
if [ -n "${S3CURL_LOG:-}" ]; then
  while ! mkdir "$S3CURL_LOG.lock" 2>/dev/null; do
    sleep 0.01
  done
  if [ -f "$S3CURL_LOG.count" ]; then
    count=$(cat "$S3CURL_LOG.count")
  fi
  count=$((count + 1))
  printf '%s\n' "$count" > "$S3CURL_LOG.count"
  config="$S3CURL_LOG.$count.config"
else
  config=$(mktemp "${TMPDIR:-/tmp}/s3curl.XXXXXX")
fi
cat <&3 > "$config"
if [ -n "${S3CURL_LOG:-}" ]; then
  escaped=$(od -An -v -tx1 "$config" | awk '
    function hv(h,   i, n) { n = 0; for (i = 1; i <= length(h); i++) n = n * 16 + index("0123456789abcdef", substr(h, i, 1)) - 1; return n }
    { for (i = 1; i <= NF; i++) { if ($i == "25") printf "%%25"; else if ($i == "09") printf "%%09"; else if ($i == "0a") printf "%%0A"; else printf "%c", hv($i) } }')
  # The configuration through the environment: awk's -v would turn its `\n` into a newline.
  S3CURL_LOGGED_CONFIG=$escaped awk -v uid="$(id -u)" -v fds="${fds:--}" 'BEGIN {
    line = "uid=" uid "\tfds=" fds "\tconfig=" ENVIRON["S3CURL_LOGGED_CONFIG"]
    for (i = 1; i < ARGC; i++) {
      a = ARGV[i]
      gsub(/%/, "%25", a)
      gsub(/\t/, "%09", a)
      gsub(/\n/, "%0A", a)
      line = line "\t" a
    }
    print line
    exit
  }' "$@" >> "$S3CURL_LOG"
  rmdir "$S3CURL_LOG.lock"
fi

if [ -n "${S3CURL_REAL:-}" ] && { [ -z "${S3CURL_REAL_ONLY:-}" ] || grep -qx "request = \"$S3CURL_REAL_ONLY\"" "$config"; }; then
  exec 3<"$config"
  if [ -z "${S3CURL_LOG:-}" ]; then
    rm -f "$config"
  fi
  exec "$S3CURL_REAL" -q -K /dev/fd/3
fi

# The configuration's values: `name = "value"` lines.
conf() {
  sed -n "s/^$1 = \"\\(.*\\)\"\$/\\1/p" "$config" | head -n 1
}
method=$(conf request)
checksum=$(sed -n 's/^header = "x-amz-checksum-sha256: \(.*\)"$/\1/p' "$config" | head -n 1)
fail_on_error=0
if grep -qx 'fail' "$config"; then
  fail_on_error=1
fi
compressed=0
if grep -qx 'compressed' "$config"; then
  compressed=1
fi
# S11: `max-filesize = N` (the shim writes it unquoted).
max_filesize=$(sed -n 's/^max-filesize = "*\([0-9][0-9]*\)"*$/\1/p' "$config" | head -n 1)
# S11 (LD-19): a write-out that asks how many redirects were followed (the claude relay's release GET) is told 0.
redirects=
if grep -q '%{num_redirects}' "$config"; then
  redirects=" redirects=0"
fi
if [ -z "${S3CURL_LOG:-}" ]; then
  rm -f "$config"
fi

if [ -n "${S3CURL_FAIL:-}" ]; then
  exit "$S3CURL_FAIL"
fi
if [ -n "${S3CURL_SLOW_MS:-}" ]; then
  sleep "$(awk -v ms="$S3CURL_SLOW_MS" 'BEGIN { printf "%.3f", ms / 1000 }')"
fi
status=${S3CURL_STATUS:-200}
over=0
case "$method" in
  PUT)
    if [ -n "${S3CURL_SAVE:-}" ]; then
      mkdir -p "$S3CURL_SAVE"
      cat > "$S3CURL_SAVE/$count.put"
    else
      cat > /dev/null
    fi
    ;;
  GET)
    if [ "$status" -lt 400 ]; then
      body=""
      if [ -n "${S3CURL_BODIES:-}" ] && [ -f "$S3CURL_BODIES/$count" ]; then
        body="$S3CURL_BODIES/$count"
      elif [ -n "${S3CURL_BODY:-}" ]; then
        body=$S3CURL_BODY
      fi
      if [ -n "$body" ]; then
        # S11: curl compares the advertised size (the stored bytes) with max-filesize before the transfer.
        if [ -n "$max_filesize" ] && [ "$(($(wc -c < "$body")))" -gt "$max_filesize" ]; then
          over=1
        # S11: a gzip-stored body is written decoded only when the configuration asks (`compressed`).
        elif [ "${S3CURL_ENCODING:-}" = "gzip" ] && [ "$compressed" = "1" ]; then
          /usr/bin/gzip -dc < "$body" || exit 61
        else
          cat "$body"
        fi
      fi
    fi
    ;;
esac
if [ "$status" -ge 400 ] && ! { [ "$method" = "GET" ] && [ "$fail_on_error" = "1" ]; }; then
  printf '<Error><Code>%s</Code></Error>' "${S3CURL_CODE:-AccessDenied}"
fi
if [ "$over" = "1" ]; then
  echo "curl: (63) Maximum file size exceeded" >&2
fi
printf 'ai-env-curl status=%s version=%s checksum=%s etag="fake-%s"%s\n' "$status" "${S3CURL_VERSION:-fake-version-$count}" "$checksum" "$count" "$redirects" >&2
if [ "$over" = "1" ]; then
  exit 63
fi
exit 0
