# Lab attacker: standard pentest tools, runs only on the internal `lab` network under compose
# profile `attack`. Non-root; the scenarios need no privileges.
FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends hydra curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home attacker
COPY --chmod=755 . /attack
RUN chown -R attacker /attack
USER attacker
WORKDIR /attack
ENTRYPOINT ["/bin/bash"]
CMD ["run_all.sh"]
