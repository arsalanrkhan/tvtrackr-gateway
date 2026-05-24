package com.tvtrackr.gateway.properties;

import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "app.resilience")
public class ResilienceProperties {

  private CircuitBreakerProperties defaults;
  private Map<String, CircuitBreakerProperties> instances;

  @Getter
  @Setter
  public static class CircuitBreakerProperties {
    private Integer slidingWindowSize;
    private Float failureRateThreshold;
    private Integer waitDurationInOpenStateSeconds;
    private Integer permittedCallsInHalfOpenState;
  }
}
