# syntax=docker/dockerfile:1.26@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# Adapted from yshalsager/logseq-selfhost images/sync/Dockerfile (AGPL-3.0).
# Changes Copyright (c) 2026 Colin Knapp, https://colinknapp.com
# SPDX-License-Identifier: AGPL-3.0-only
FROM debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd AS dependencies
ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive MISE_YES=1
ENV PATH=/root/.local/bin:$PATH
RUN apt-get update \
  && apt-get install -y --no-install-recommends bash ca-certificates curl git xz-utils python3 \
  && rm -rf /var/lib/apt/lists/*
# Fetch a fixed release binary, not an executable floating installer script.
RUN case "$TARGETARCH" in \
      amd64) arch=x64; checksum=a6ac620e73fb58cefbdfef8fb154856fbd8ae08d75ae88103e4b81daef3a836e;; \
      arm64) arch=arm64; checksum=7a4032ee0f637e2333b78ef937bdffc90efed799a4a85fa64c393799cc428731;; \
      *) exit 1;; esac \
  && mkdir -p /root/.local/bin \
  && curl -fsSL "https://github.com/jdx/mise/releases/download/v2026.10.23/mise-v2026.10.23-linux-$arch" -o /root/.local/bin/mise \
  && echo "$checksum  /root/.local/bin/mise" | sha256sum -c - \
  && chmod 755 /root/.local/bin/mise
WORKDIR /tooling
COPY server/mise.toml /tooling/mise.toml
RUN mise trust /tooling/mise.toml && mise install node java clojure
WORKDIR /src
RUN git init . \
  && git remote add origin https://github.com/logseq/logseq.git \
  && git fetch --depth 1 origin 69da7e2215b336cc5123dafb2a1686996e39596c \
  && git checkout --detach FETCH_HEAD \
  && test "$(git rev-parse HEAD)" = 69da7e2215b336cc5123dafb2a1686996e39596c
COPY server/mise.toml /src/mise.toml
COPY server/patch-source.py /tmp/patch-source.py
RUN mise trust /src/mise.toml && python3 /tmp/patch-source.py /src
# Include complete original source plus the exact source patch in the image.
RUN git archive --format=tar HEAD | gzip -n > /tmp/logseq-source.tar.gz
WORKDIR /src/deps/db-sync
RUN mise exec -- corepack enable
# Keep this package's dependencies self-contained; do not inherit root hoisting.
RUN --mount=type=cache,target=/root/.local/share/pnpm/store mise exec -- pnpm install --frozen-lockfile --ignore-workspace
# Keep Maven/Git dependencies in the exported layer: ephemeral runner caches
# disappear when the runner is reclaimed.
RUN mise exec -- clojure -P -M:cljs

FROM dependencies AS build
RUN mise exec -- pnpm run build:node-adapter
RUN CI=true mise exec -- pnpm prune --prod --ignore-workspace
RUN mkdir -p /tmp/runtime-data

FROM gcr.io/distroless/nodejs24-debian12:nonroot@sha256:14d42e2511532589a7c7e01a753667a74fcc96266e137e8125006b87b0c32d0a
WORKDIR /app
LABEL org.opencontainers.image.description="Operator-authorized Logseq sync server" \
      org.opencontainers.image.source="https://github.com/Leopere/logseq-selfhost-server" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.authors="Colin Knapp <https://colinknapp.com>" \
      org.opencontainers.image.upstream-revision="69da7e2215b336cc5123dafb2a1686996e39596c"
COPY --chown=nonroot:nonroot --from=build /src/deps/db-sync/package.json /app/package.json
COPY --chown=nonroot:nonroot --from=build /src/deps/db-sync/pnpm-lock.yaml /app/pnpm-lock.yaml
COPY --chown=nonroot:nonroot --from=build /src/deps/db-sync/node_modules /app/node_modules
COPY --chown=nonroot:nonroot --from=build /src/deps/db-sync/worker /app/worker
COPY --chown=nonroot:nonroot --from=build /tmp/runtime-data /app/data
COPY --from=build /tmp/logseq-source.tar.gz /app/corresponding-source/logseq-source.tar.gz
COPY --from=build /src/LICENSE.md /app/corresponding-source/UPSTREAM-LICENSE.md
COPY server/ /app/corresponding-source/server/
COPY LICENSE NOTICE LICENSING.md compose.yaml compose.public.yaml /app/corresponding-source/
COPY third_party/ /app/corresponding-source/third_party/
COPY --chown=nonroot:nonroot server/auth/ /app/auth/
COPY server/admin/ /app/admin/
ENV DB_SYNC_PORT=8787 DB_SYNC_DATA_DIR=/app/data DB_SYNC_STORAGE_DRIVER=sqlite \
    DB_SYNC_ASSETS_DRIVER=filesystem DB_SYNC_LOG_LEVEL=warn \
    LOGSEQ_GRANTS_FILE=/app/data/grants.json
USER nonroot:nonroot
EXPOSE 8787
CMD ["/app/auth/entrypoint.cjs"]
