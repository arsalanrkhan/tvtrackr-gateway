# tvtrackr-gateway

The single entry point for the TVTrackr backend (port `8080`). Validates JWTs, forwards trusted user-identity headers downstream, routes requests to services, and circuit-breaks failing downstream calls. Built on **Spring Cloud Gateway MVC** (the servlet-based variant, not reactive WebFlux) — chosen for consistency with the rest of the stack, which runs on Spring MVC/Tomcat.

## Request flow

```
Client → Gateway
           ├─ public route? → skip auth, still circuit-broken
           └─ protected route → validate JWT (RSA public key)
                                  ├─ invalid/missing → 401, request stops here
                                  └─ valid → inject X-User-Id / X-User-Email-Verified
                                              → circuit breaker check
                                                 ├─ open → 503 immediately, no downstream call
                                                 └─ closed/half-open → forward to service
```

## Key components

### `JwtAuthenticationFilter`
A `OncePerRequestFilter` that runs before Spring Security's auth filter. For each request it:
1. Resolves which downstream service the path belongs to (`app.gateway.service-routes`), for circuit-breaker naming and logging.
2. Resolves or generates an `X-Correlation-Id` (reuses an inbound one if present, otherwise generates a UUID) for request tracing across services.
3. If the path matches `app.gateway.public-routes` (currently `/api/auth/v1/**`), skips JWT validation entirely.
4. Otherwise requires a `Bearer` token in `Authorization`, verifies it with the RSA **public** key, and extracts `sub` (user UUID) and the `emailVerified` claim.
5. Wraps the request in a `HeaderMutatingRequest` that injects `X-User-Id` and `X-User-Email-Verified` — and **overrides `getHeader()`** so a client can't spoof these by setting them directly; whatever the client sent gets shadowed by the gateway's own values.
6. Runs the downstream call through a per-service Resilience4j circuit breaker.

### `HeaderMutatingRequest`
An `HttpServletRequestWrapper` that intercepts `getHeader`, `getHeaders`, and `getHeaderNames` for exactly three header names (`X-User-Id`, `X-User-Email-Verified`, `X-Correlation-Id`) and substitutes gateway-computed values, falling through to the real request for everything else.

### Circuit breaking (`ResilienceConfig`, `ResilienceProperties`)
- One `CircuitBreakerRegistry` bean builds a **default** circuit breaker config from `app.resilience.defaults`, then layers any per-service overrides from `app.resilience.instances` on top (each field falls back to the default if not overridden).
- Breakers are scoped **per downstream service**, not per endpoint — documented in code as a known tradeoff: one bad endpoint (e.g. a broken `/reset-password`) can trip the circuit for the whole service, including healthy endpoints like `/login`. The noted long-term fix is per-resource-group or infrastructure-level (Nginx/Envoy) circuit breaking.
- Implemented **programmatically** inside `JwtAuthenticationFilter` (`tryAcquirePermission`, `onSuccess`, `onError`) rather than via Spring Cloud Gateway's declarative `CircuitBreaker` route filter — that YAML-based approach doesn't work here because `CircuitBreakerFactory` isn't auto-configured for the WebMVC gateway stack in Spring Boot 4.
- Network-level failures (`ResourceAccessException`, `IOException`) count as circuit-breaker errors; other exceptions during the downstream call are logged and turned into a `503` without tripping the breaker.

### JWT verification (`JwtProperties`)
Loads the RSA **public** key once at startup from the `JWT_PUBLIC_KEY` env var (Base64-encoded X.509). The gateway can verify tokens signed by `auth-service` but never signs its own — it holds no private key. Code comments note that key rotation currently requires a gateway restart; a JWKS endpoint with periodic refresh is flagged as a future improvement.

### Security (`SecurityConfig`)
- CSRF disabled (stateless API, no cookie-based session auth at this layer).
- Stateless session policy.
- CORS restricted to a single configured origin (`app.frontend.base-url`), allowing standard methods and exposing `X-Correlation-Id` to the browser; credentials (cookies) allowed.
- All requests are `permitAll()` at the Spring Security level — actual authorization happens in `JwtAuthenticationFilter`, which runs before Spring Security's own authentication filter.

### Errors (`GatewayErrors`)
Gateway-specific `BusinessErrors` subclass (prefix `GW`): `UNAUTHORIZED`, `INVALID_TOKEN`, `MISSING_TOKEN` (all 401), `SERVICE_UNAVAILABLE` (503, returned when a circuit is open or a downstream call fails).

## Routing

Routes live under `spring.cloud.gateway.server.webmvc.routes` in `application.yaml`. Each route gets a `connect-timeout` / `response-timeout` (in `metadata`) tuned slightly *longer* than the downstream service's own server timeout, so the service can abort cleanly first rather than the gateway timing out mid-request. Currently one route is configured:

| Route | Path | Target |
|---|---|---|
| `auth-service` | `/api/auth/v1/**` | `${AUTH_SERVICE_URL}` |

New downstream services are added as new route entries as they're built.

## Tech stack

- Java 25, Spring Boot 4.0.6
- Spring Cloud Gateway Server WebMVC (`spring-cloud` 2025.1.1)
- Spring Security (filter-chain only, no session auth)
- JJWT 0.12.6 (RSA / RS256, verification only)
- Resilience4j Circuit Breaker 2.4.0
- `tvtrackr-common` (error handling)

## Configuration (env vars)

| Variable | Purpose |
|---|---|
| `JWT_PUBLIC_KEY` | Base64-encoded RSA public key used to verify access tokens |
| `AUTH_SERVICE_URL` | Base URL of `auth-service` for the gateway route |
| `FRONTEND_BASE_URL` | Allowed CORS origin |

Resilience defaults (`sliding-window-size: 10`, `failure-rate-threshold: 50%`, `wait-duration: 30s`, `permitted-half-open-calls: 3`) live in `application.yaml` under `app.resilience.defaults` and apply to any service not explicitly listed under `app.resilience.instances`.

## Running locally

`docker-compose.yml` spins up Postgres, Redis, `auth-service` (built from `../auth-service`), and the gateway together:

```bash
docker compose up --build
```

## Actuator

`/actuator/health` and `/actuator/info` are exposed; health detail is hidden (`show-details: never`) so internals aren't leaked publicly.
