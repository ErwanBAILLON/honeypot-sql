# honeypot-sql: static binary on distroless, runs as nonroot (uid 65532).
# go.mod requires Go 1.26 (pulled in by pgx v5.11).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/honeypot-sql ./cmd/honeypot-sql

# Offline IP->ASN/country table for source attribution. iptoasn.com publishes it
# in the public domain (RouteViews data), so it is redistributable and fits an
# open-source image. Fetched here, at build time, where the network is allowed;
# the running honeypot only ever reads the local file. Best-effort: if the
# download fails the build still succeeds and attribution is simply off.
RUN apk add --no-cache ca-certificates wget \
 && (wget -q -O /out/ip2asn.tsv.gz https://iptoasn.com/data/ip2asn-combined.tsv.gz \
     || echo "WARNING: ip2asn download failed; attribution will be off") \
 && touch /out/ip2asn.tsv.gz

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/honeypot-sql /honeypot-sql
COPY --from=build /out/ip2asn.tsv.gz /ip2asn.tsv.gz
USER nonroot:nonroot
EXPOSE 3306 5432 8080
ENTRYPOINT ["/honeypot-sql"]
CMD ["serve"]
