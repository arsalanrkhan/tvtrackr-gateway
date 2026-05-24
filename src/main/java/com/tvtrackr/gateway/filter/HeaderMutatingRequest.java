package com.tvtrackr.gateway.filter;

import com.tvtrackr.gateway.constant.Headers;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class HeaderMutatingRequest extends HttpServletRequestWrapper {

  private final String userId;
  private final boolean emailVerified;
  private final String correlationId;

  public HeaderMutatingRequest(
      HttpServletRequest request, String userId, boolean emailVerified, String correlationId) {
    super(request);
    this.userId = userId;
    this.emailVerified = emailVerified;
    this.correlationId = correlationId;
  }

  @Override
  public String getHeader(String name) {
    if (Headers.X_USER_ID.equalsIgnoreCase(name)) return userId;
    if (Headers.X_USER_EMAIL_VERIFIED.equalsIgnoreCase(name)) return String.valueOf(emailVerified);
    if (Headers.X_CORRELATION_ID.equalsIgnoreCase(name)) return String.valueOf(correlationId);
    return super.getHeader(name);
  }

  @Override
  public Enumeration<String> getHeaders(String name) {
    if (Headers.X_USER_ID.equalsIgnoreCase(name))
      return Collections.enumeration(Collections.singletonList(userId));
    if (Headers.X_USER_EMAIL_VERIFIED.equalsIgnoreCase(name))
      return Collections.enumeration(Collections.singletonList(String.valueOf(emailVerified)));
    if (Headers.X_CORRELATION_ID.equalsIgnoreCase(name))
      return Collections.enumeration(Collections.singletonList(String.valueOf(correlationId)));
    return super.getHeaders(name);
  }

  @Override
  public Enumeration<String> getHeaderNames() {
    Set<String> names =
        Collections.list(super.getHeaderNames()).stream()
            .filter(
                n ->
                    !Headers.X_USER_ID.equalsIgnoreCase(n)
                        && !Headers.X_USER_EMAIL_VERIFIED.equalsIgnoreCase(n)
                        && !Headers.X_CORRELATION_ID.equalsIgnoreCase(n))
            .collect(Collectors.toCollection(LinkedHashSet::new));
    names.add(Headers.X_USER_ID);
    names.add(Headers.X_USER_EMAIL_VERIFIED);
    names.add(Headers.X_CORRELATION_ID);
    return Collections.enumeration(names);
  }
}
