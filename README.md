# dalogin-quarkus

Authentication and session gateway for the Cinemas booking platform. Migrated from WildFly to Quarkus with `quarkus-undertow` (servlet-based).

## What it does

- **Login** — HMAC-SHA512 handshake (`POST /login/HelloWorld`), password verification via stored procedure, session creation with XSRF-TOKEN generation.
- **Session management** — HTTP sessions with JSESSIONID, X-Token (token2), and AES-encrypted XSRF-TOKEN cookies.
- **User retrieval** — `GET /login/admin` validates session + XSRF, then proxies to `mbook-quarkus` via `ServiceClient` to fetch the user profile.
- **Registration** — Voucher-based (`/Registration`) and open (`/RegistrationWithoutVoucher`) user sign-up with email activation flow.
- **Password reset** — Forgot-password email flow (`/ChangePassword` → `/ChangePasswordCode` → `/ChangePasswordNewPassword`).
- **Proxy to mbooks** — `CheckOut`, `GetAllPurchases`, `ManagePurchases` forward requests to the booking service, injecting session-derived headers.
- **Static UI** — AngularJS 1.x login/register/movies pages served from `src/main/resources/META-INF/resources/`.

## Architecture

```
Client (iOS / Web)
  │  HMAC-SHA512 handshake
  ▼
dalogin (:8080, /login)
  ├── HelloWorld servlet ── MySQL login_ (get_hash, insert_device_, get_token2)
  ├── AuthFilter ── validates XSRF-TOKEN cookie
  ├── AdminServlet ── ServiceClient → mbook /rest/user/{user}/{token1}
  └── CheckOut/Purchases ── ServiceClient → mbooks /rest/book/...
```

## Key components

| Component | Purpose |
|-----------|---------|
| `HelloWorld` servlet | Login entry point — HMAC verification, session + token creation |
| `AuthFilter` | Guards `/admin`, `/CheckOut`, `/GetAllPurchases`, `/ManagePurchases`, `/logout` — checks session + XSRF cookie |
| `ServiceClient` | RESTEasy client that proxies requests to mbook/mbooks with forwarded headers (X-Token, Ciphertext, cookies, uuid, token2, TIME_) |
| `SQLAccess` | Static JDBC layer wrapping stored-procedure calls to `login_` database |
| `DBConnectionManager` | Raw JDBC connections; catalog set from `SystemConstants.DB_CATALOG` |
| `SystemConstants` | Centralized config — `DB_CATALOG` (from `DB_URL` env var), `getServiceUrl()` (from `WILDFLY_URL` env var) |

## Database

Uses MySQL schema **`login_`** (not `login`) via raw JDBC and stored procedures.

Key tables: `logins`, `devices`, `device_states`, `Last_seen`, `Tokens`, `vouchers`, `voucher_states`, `forgotPsw`.

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_URL` | `jdbc:mysql://localhost:3306/login_` | JDBC URL for the login_ database |
| `WILDFLY_URL` | `http://localhost:8888` | Base URL for downstream services (Apache proxy in K8s) |

## Build & Run

```bash
./mvnw quarkus:dev                    # dev mode on port 8080
./mvnw package -DskipTests            # package for container
podman build -t dalogin-quarkus:local .
```

## Part of the Cinemas platform

| Service | Repo | Role |
|---------|------|------|
| **dalogin-quarkus** | this repo | Auth gateway |
| mbook-quarkus | [igeorge0902/mbook-quarkus](https://github.com/igeorge0902/mbook-quarkus) | User/device API |
| mbooks-quarkus | [igeorge0902/mbooks-quarkus](https://github.com/igeorge0902/mbooks-quarkus) | Movie/booking/payment API |
| simple-service-webapp-quarkus | [igeorge0902/simple-service-webapp-quarkus](https://github.com/igeorge0902/simple-service-webapp-quarkus) | Image server |
| k8infra | [igeorge0902/k8infra](https://github.com/igeorge0902/k8infra) | Kubernetes manifests, SQL fixes, deploy runbook |
