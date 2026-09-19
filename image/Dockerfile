# S0 placeholder image: only the shim binary. The real image (claude 2.1.278
# pinned by SHA-256, uid 1000, the reviewed /Users/mike/.claude subset) lands
# in stage S3. `make vm-build` copies the cross-built binary to image/ai-env.
FROM public.ecr.aws/lambda/microvms:al2023-minimal
COPY ai-env /usr/local/bin/ai-env
EXPOSE 8080 9000 9418
ENTRYPOINT ["/usr/local/bin/ai-env","shim","--app-port","8080","--hooks-port","9000","--code-port","9418","--claude","/usr/local/bin/claude","--home","/Users/mike","--uid","1000"]
