FROM jaegertracing/all-in-one@sha256:304af35ea63d77005a545b01f612634defa086448632107ddf39aa5641c8724d
HEALTHCHECK \
    --interval=1s \
    --timeout=1s \
    --start-period=1s \
    --retries=60 \
    CMD wget -q --header='Content-Type:application/json' -O - http://localhost:14269/health | grep "Server available"
