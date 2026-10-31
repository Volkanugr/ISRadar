FROM rust:1-bookworm AS build
ARG AGENT_FEATURES=""
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.* ./
COPY external-agent ./external-agent
COPY scripts/docker-build.sh /tmp/docker-build.sh
RUN sh /tmp/docker-build.sh

FROM debian:bookworm-slim
# The runner enables ICMP datagram sockets with ping_group_range. Remove
# package-installed file privileges so ping can exec with --cap-drop ALL.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iputils-ping libpcap0.8 libcap2-bin \
    && if [ -n "$(getcap /bin/ping)" ]; then setcap -r /bin/ping; fi \
    && chmod u-s,g-s /bin/ping \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 agent && useradd --uid 10001 --gid 10001 --no-create-home agent
COPY --from=build /src/target/release/external-agent /usr/local/bin/external-agent
USER 10001:10001
WORKDIR /data
ENTRYPOINT ["external-agent"]
CMD ["vectors", "list"]

