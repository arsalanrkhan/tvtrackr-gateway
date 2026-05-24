package com.tvtrackr.gateway.filter;

import com.tvtrackr.common.error.ErrorResponseDTO;
import com.tvtrackr.gateway.exception.GatewayErrors;
import com.tvtrackr.gateway.properties.GatewayProperties;
import com.tvtrackr.gateway.properties.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
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
  private final AntPathMatcher pathMatcher = new AntPathMatcher();
  private final ObjectMapper objectMapper;

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    String path = request.getRequestURI();

    if (isPublicRoute(path)) {
      filterChain.doFilter(request, response);
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
      boolean emailVerified = Boolean.TRUE.equals(claims.get("emailVerified", Boolean.class));

      filterChain.doFilter(new HeaderMutatingRequest(request, userId, emailVerified), response);

    } catch (Exception e) {
      log.warn("[JwtAuthFilter] Invalid token for path={}: {}", path, e.getMessage());
      writeError(response, GatewayErrors.UNAUTHORIZED);
    }
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
}
