package com.tvtrackr.gateway.filter;

import com.tvtrackr.common.error.ErrorResponseDTO;
import com.tvtrackr.gateway.constant.Headers;
import com.tvtrackr.gateway.exception.GatewayErrors;
import com.tvtrackr.gateway.properties.GatewayProperties;
import com.tvtrackr.gateway.properties.JwtProperties;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.server.PathContainer;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import tools.jackson.databind.ObjectMapper;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final GatewayProperties gatewayProperties;
  private final JwtProperties jwtProperties;
  private final CircuitBreakerRegistry circuitBreakerRegistry;
  private final ObjectMapper objectMapper;

  private List<PathPattern> compiledPublicRoutes;

  @PostConstruct
  public void init() {
    PathPatternParser parser = new PathPatternParser();
    List<String> routes = gatewayProperties.getPublicRoutes();
    this.compiledPublicRoutes =
        routes != null ? routes.stream().map(parser::parse).toList() : List.of();
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    String path = request.getRequestURI();
    String serviceName = resolveServiceName(path);
    String correlationId = resolveCorrelationId(request, path, serviceName);

    if (isPublicRoute(path)) {
      executeWithCircuitBreaker(
          path,
          serviceName,
          new HeaderMutatingRequest(request, null, false, correlationId),
          response,
          filterChain);
      return;
    }

    String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      writeError(response, GatewayErrors.MISSING_TOKEN);
      return;
    }

    String token = authHeader.substring(7);
    try {
      Claims claims =
          Jwts.parser()
              .verifyWith(jwtProperties.getRsaPublicKey())
              .build()
              .parseSignedClaims(token)
              .getPayload();

      String userId = claims.getSubject();
      if (userId == null) {
        throw new JwtException("Missing sub claim");
      }
      boolean emailVerified = Boolean.TRUE.equals(claims.get("emailVerified", Boolean.class));

      executeWithCircuitBreaker(
          path,
          serviceName,
          new HeaderMutatingRequest(request, userId, emailVerified, correlationId),
          response,
          filterChain);

    } catch (Exception e) {
      log.warn("[JwtAuthFilter] Invalid token for path={}: {}", path, e.getMessage());
      writeError(response, GatewayErrors.INVALID_TOKEN);
    }
  }

  private void executeWithCircuitBreaker(
      String path,
      String serviceName,
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain)
      throws IOException {
    CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(serviceName);
    try {
      circuitBreaker.executeCheckedRunnable(() -> filterChain.doFilter(request, response));
    } catch (CallNotPermittedException e) {
      log.warn("[CircuitBreaker] Circuit open for service={}", serviceName);
      writeError(response, GatewayErrors.SERVICE_UNAVAILABLE);
    } catch (Throwable e) {
      if (e instanceof Error error) {
        throw error;
      }
      log.error(
          "[CircuitBreaker] Error forwarding request to service={}: {}",
          serviceName,
          e.getMessage());
      writeError(response, GatewayErrors.SERVICE_UNAVAILABLE);
    }
  }

  private String resolveServiceName(String path) {
    Map<String, String> serviceRoutes = gatewayProperties.getServiceRoutes();
    if (serviceRoutes != null) {
      return serviceRoutes.entrySet().stream()
          .filter(e -> path.startsWith(e.getValue()))
          .max(Comparator.comparingInt(e -> e.getValue().length()))
          .map(Map.Entry::getKey)
          .orElseGet(
              () -> {
                log.warn(
                    "[CircuitBreaker] No service mapping found for path={}, using default circuit breaker",
                    path);
                return "default";
              });
    }
    log.warn(
        "[CircuitBreaker] No service mapping found for path={}, using default circuit breaker",
        path);
    return "default";
  }

  private boolean isPublicRoute(String path) {
    PathContainer pathContainer = PathContainer.parsePath(path);
    return compiledPublicRoutes.stream().anyMatch(pattern -> pattern.matches(pathContainer));
  }

  private void writeError(HttpServletResponse response, GatewayErrors error) throws IOException {
    response.setStatus(error.getHttpStatus());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    ErrorResponseDTO body =
        ErrorResponseDTO.builder().code(error.getCode()).desc(error.getDesc()).build();
    objectMapper.writeValue(response.getWriter(), body);
  }

  private String resolveCorrelationId(HttpServletRequest request, String path, String serviceName) {
    String existing = request.getHeader(Headers.X_CORRELATION_ID);
    String corelationId =
        (existing != null && !existing.isBlank()) ? existing : UUID.randomUUID().toString();
    log.debug("[Gateway] correlationId={} path={} service={}", corelationId, path, serviceName);
    return corelationId;
  }
}
