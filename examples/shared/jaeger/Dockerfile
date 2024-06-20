FROM jaegertracing/all-in-one@sha256:29068a1529d0bcad36bfac3e7829a8f206039b89a0db73f8bb26912c618aa114
HEALTHCHECK \
    --interval=1s \
    --timeout=1s \
    --start-period=1s \
    --retries=60 \
    CMD wget -q --header='Content-Type:application/json' -O - http://localhost:14269/health | grep "Server available"
