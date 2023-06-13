FROM jaegertracing/all-in-one@sha256:818dddceca953af2ef29ab819d123994a95b4414fb840f0d2220965affe61237
HEALTHCHECK \
    --interval=1s \
    --timeout=1s \
    --start-period=1s \
    --retries=60 \
    CMD wget -q --header='Content-Type:application/json' -O - http://localhost:14269/health | grep "Server available"
