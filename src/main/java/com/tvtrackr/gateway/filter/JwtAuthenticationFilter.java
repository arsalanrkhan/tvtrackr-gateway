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
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final GatewayProperties gatewayProperties;
  private final JwtProperties jwtProperties;
  private final CircuitBreakerRegistry circuitBreakerRegistry;
  private final ObjectMapper objectMapper;
  private final AntPathMatcher pathMatcher = new AntPathMatcher();

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
      for (Map.Entry<String, String> entry : serviceRoutes.entrySet()) {
        if (path.startsWith(entry.getValue())) {
          return entry.getKey();
        }
      }
    }
    log.warn(
        "[CircuitBreaker] No service mapping found for path={}, using default circuit breaker",
        path);
    return "default";
  }

  private boolean isPublicRoute(String path) {
    List<String> publicRoutes = gatewayProperties.getPublicRoutes();
    return publicRoutes != null
        && publicRoutes.stream().anyMatch(pattern -> pathMatcher.match(pattern, path));
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
