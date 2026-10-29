# The deliberate victim: sshd + nginx + rsyslog writing to the shared `logs` volume.
# It runs as root because sshd needs it; this is the one documented exception to the
# non-root rule, and it only ever sits on the internal `lab` network.
FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server nginx-light rsyslog \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /var/log/lab \
    && useradd --create-home --shell /bin/bash labuser
COPY sshd_config /etc/ssh/sshd_config
COPY nginx.conf /etc/nginx/nginx.conf
COPY rsyslog.conf /etc/rsyslog.conf
COPY --chmod=755 entrypoint.sh /entrypoint.sh
EXPOSE 22 80
ENTRYPOINT ["/entrypoint.sh"]
