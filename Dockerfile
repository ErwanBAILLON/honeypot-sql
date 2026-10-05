# honeypot-sql: static binary on distroless, runs as nonroot (uid 65532).
# go.mod requires Go 1.26 (pulled in by pgx v5.11).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/honeypot-sql ./cmd/honeypot-sql

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/honeypot-sql /honeypot-sql
USER nonroot:nonroot
EXPOSE 3306 5432 8080
ENTRYPOINT ["/honeypot-sql"]
CMD ["serve"]
