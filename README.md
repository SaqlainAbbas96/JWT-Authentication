# Authentication API

A production-oriented authentication API built with **.NET 10, PostgreSQL, and Clean Architecture**.

The project demonstrates production-grade authentication beyond basic JWT issuance, with a focus on **secure token lifecycle management, resilience, observability, integration testing, and containerised deployment**.

---

## Key Features

* JWT access-token authentication
* Secure opaque refresh tokens
* SHA-256 refresh-token hashing at rest
* Refresh-token rotation and single-use enforcement
* Refresh-token reuse detection and token-family revocation
* Session isolation
* PBKDF2 password hashing
* Atomic user registration and default-role assignment
* EF Core retry strategy for resilient database operations
* Authentication endpoint rate limiting
* Secure-by-default endpoint authorization
* FluentValidation and `ProblemDetails`
* CORS and security headers
* Request cancellation propagation
* Liveness and readiness health checks
* Structured logging and correlation IDs
* OpenTelemetry tracing
* PostgreSQL integration tests with Testcontainers
* GitHub Actions CI and dependency vulnerability scanning
* Production multi-stage Docker image
* Non-root container execution

---

## Architecture

The API follows **Clean Architecture**, with dependencies pointing inward toward the application and domain layers.

```text
┌─────────────────────────────┐
│     Authentication.Api      │
│                             │
│ Endpoints · Middleware      │
│ Configuration · HTTP        │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│  Authentication.Application│
│                             │
│ Services · DTOs             │
│ Validators · Interfaces     │
└───────┬───────────────┬─────┘
        │               │
        ▼               ▼
┌───────────────┐  ┌──────────────────────┐
│     Domain    │  │    Infrastructure    │
│               │  │                      │
│ Entities      │  │ EF Core / PostgreSQL │
│ Domain models │  │ Repositories         │
└───────────────┘  │ JWT / Security       │
                   │ Persistence           │
                   └──────────────────────┘
```

### Project Structure

```text
src/
├── Authentication.Api/
├── Authentication.Application/
├── Authentication.Domain/
└── Authentication.Infrastructure/

tests/
├── Authentication.IntegrationTests/
└── Authentication.UnitTests/
```

The API handles HTTP concerns, Application contains use-case logic and abstractions, Infrastructure provides implementations, and Domain remains independent of infrastructure concerns.

---

## Authentication

### Registration

User registration and default-role assignment execute within the same database transaction.

```text
Validate request
      ↓
Create user
      ↓
Assign default role
      ↓
Commit transaction
```

If role assignment fails, the user creation is rolled back.

### Login

```text
Validate credentials
      ↓
Verify password
      ↓
Generate access token
      ↓
Generate refresh token
      ↓
Persist refresh-token hash
```

Authentication failures intentionally return generic responses to avoid revealing whether an account exists.

---

## Refresh Token Security

Refresh tokens are treated as credentials, not ordinary database values.

The implementation:

* Generates cryptographically secure opaque tokens
* Stores only SHA-256 hashes
* Associates tokens with a token family/session
* Rotates tokens on use
* Enforces single use
* Detects token reuse
* Revokes the token family when reuse is detected
* Handles expiration and revocation
* Uses PostgreSQL row locking during rotation

Example lifecycle:

```text
Refresh Token A
      │
    refresh
      ▼
Refresh Token B
      │
    refresh
      ▼
Refresh Token C
```

If an already-rotated token is reused, the token family is revoked, preventing a stolen refresh token from becoming a persistent authentication mechanism.

---

## Security

Security is implemented as multiple independent controls rather than relying solely on JWT signing.

### Passwords

Passwords are protected using **PBKDF2 hashing** and are never stored in plaintext.

### JWT Configuration

Security-sensitive configuration is validated at startup. Secrets are not committed to source control.

### Rate Limiting

Authentication-sensitive endpoints are protected by a fixed-window rate limiter with `Retry-After` support.

### Authorization

The application uses a secure-by-default authorization policy. Public authentication endpoints explicitly allow anonymous access; protected endpoints require authorization.

### HTTP Security

The API provides:

* CORS configuration
* `X-Content-Type-Options`
* `X-Frame-Options`
* `Referrer-Policy`
* `Permissions-Policy`

---

## Resilience & Error Handling

### Database Resilience

PostgreSQL uses EF Core's execution strategy with retry-on-failure support. Explicit transactions are executed through a retry-aware abstraction.

### Request Cancellation

Cancellation tokens are propagated through application, repository, and EF Core operations.

### Error Handling

Centralized exception handling maps known failures to appropriate `ProblemDetails` responses:

| Error            | Status |
| ---------------- | -----: |
| Validation       |  `400` |
| Authentication   |  `401` |
| Conflict         |  `409` |
| Unexpected error |  `500` |

Unexpected implementation details are not exposed to clients.

---

## Observability

### Structured Logging

Application logging uses structured `ILogger<T>` messages without logging passwords, tokens, or other authentication credentials.

### Correlation IDs

Each request receives a correlation ID that can be used to trace related log activity.

### Health Checks

```text
GET /health/live
GET /health/ready
```

* `/health/live` — application liveness
* `/health/ready` — application + PostgreSQL readiness

### OpenTelemetry

Instrumentation is available for:

* ASP.NET Core
* HTTP clients
* Entity Framework Core
* .NET runtime

Telemetry can be exported through OTLP and is disabled by default.

---

## Testing

The project includes unit and integration test projects, with important application behaviour covered through **HTTP integration tests against a real PostgreSQL instance running in Testcontainers**.

Tests cover areas including:

* Registration and login
* JWT authentication
* Refresh-token rotation and reuse detection
* Token-family revocation
* Logout and session isolation
* Validation and authentication failures
* Rate limiting
* CORS and authorization boundaries
* Health checks and correlation IDs
* Transaction rollback
* Database retry behaviour

Run the test suite:

```bash
dotnet test --configuration Release
```

---

## CI/CD

GitHub Actions validates pushes and pull requests targeting `master`.

```text
Restore
  ↓
Dependency vulnerability check
  ↓
Build
  ↓
Test
  ↓
Docker image build
```

Dependency scanning:

```bash
dotnet list package --vulnerable --include-transitive
```

The pipeline also verifies that the production Docker image builds successfully.

---

## Docker

The application uses a multi-stage Docker build with the final image based on the .NET ASP.NET runtime.

```text
.NET SDK
  │
  ├── Restore
  ├── Build
  └── Publish
       │
       ▼
.NET ASP.NET Runtime
  │
  ├── Production configuration
  ├── HTTP :8080
  └── Non-root app user
```

### Build

```bash
docker build -t authentication-api .
```

### Run

Secrets and environment-specific configuration are supplied at runtime:

```powershell
docker run --rm -p 8080:8080 `
  -e "Jwt__Key=YOUR_TEST_JWT_SECRET" `
  -e "ConnectionStrings__Postgres=Host=host.docker.internal;Port=5432;Database=authentication;Username=postgres;Password=YOUR_PASSWORD" `
  authentication-api
```

Verify:

```bash
curl http://localhost:8080/health/live
curl http://localhost:8080/health/ready
```

No secrets are baked into the image.

---

## Technology Stack

| Area          | Technologies                                             |
| ------------- | -------------------------------------------------------- |
| Backend       | .NET 10, ASP.NET Core, C#                                |
| API           | Minimal APIs                                             |
| Database      | PostgreSQL, EF Core, Npgsql                              |
| Security      | JWT, PBKDF2, SHA-256, rate limiting                      |
| Architecture  | Clean Architecture, DI, Repository pattern               |
| Validation    | FluentValidation, ProblemDetails                         |
| Observability | `ILogger`, correlation IDs, Health Checks, OpenTelemetry |
| Testing       | xUnit, Testcontainers, PostgreSQL                        |
| DevOps        | GitHub Actions, Docker                                   |

---

## Local Development

### Prerequisites

* .NET 10 SDK
* PostgreSQL
* Docker Desktop *(optional)*

Configure local secrets using .NET User Secrets:

```bash
dotnet user-secrets set "Jwt:Key" "YOUR_LOCAL_SECRET"
dotnet user-secrets set "ConnectionStrings:Postgres" "YOUR_CONNECTION_STRING"
```

Run the API:

```bash
dotnet run --project src/Authentication.Api
```

In Development, OpenAPI and Scalar are available for API exploration.

---

## Engineering Focus

The project is intentionally designed as a **reusable authentication foundation**, not a basic JWT tutorial.

The implementation focuses on:

**Security** — secure credential and token lifecycle management
**Reliability** — resilient persistence and atomic operations
**Observability** — structured logs, correlation, health checks, and tracing
**Quality** — integration testing against real PostgreSQL
**Deployability** — CI validation and production Dockerisation

Future extensions could include password reset, email verification, account recovery, and external identity-provider integration.