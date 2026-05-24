package com.tvtrackr.gateway.config;

import com.tvtrackr.gateway.properties.ResilienceProperties;
import com.tvtrackr.gateway.properties.ResilienceProperties.CircuitBreakerProperties;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import java.time.Duration;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class ResilienceConfig {

  private final ResilienceProperties resilienceProperties;

  /**
   * Circuit breakers are scoped per downstream service, not per endpoint. A single failing endpoint
   * (e.g. /api/auth/v1/reset-password) will open the circuit for the entire service, blocking all
   * other endpoints including healthy ones (e.g. /api/auth/v1/login). At larger scale,
   * per-resource-group circuit breaking or infrastructure-level circuit breaking (Nginx upstream,
   * Envoy) would provide more precise isolation Will move circuitbreaking to nginx anyway.
   */
  @Bean
  public CircuitBreakerRegistry circuitBreakerRegistry() {
    CircuitBreakerProperties defaults = resilienceProperties.getDefaults();
    CircuitBreakerConfig defaultConfig = buildConfig(defaults, defaults);
    CircuitBreakerRegistry registry = CircuitBreakerRegistry.of(defaultConfig);

    Map<String, CircuitBreakerProperties> instances = resilienceProperties.getInstances();
    if (instances != null) {
      instances.forEach(
          (name, override) -> {
            CircuitBreakerConfig config = buildConfig(override, defaults);
            registry.circuitBreaker(name, config);
          });
    }

    return registry;
  }

  private CircuitBreakerConfig buildConfig(
      CircuitBreakerProperties props, CircuitBreakerProperties defaults) {
    return CircuitBreakerConfig.custom()
        .slidingWindowSize(resolve(props.getSlidingWindowSize(), defaults.getSlidingWindowSize()))
        .failureRateThreshold(
            resolve(props.getFailureRateThreshold(), defaults.getFailureRateThreshold()))
        .waitDurationInOpenState(
            Duration.ofSeconds(
                resolve(
                    props.getWaitDurationInOpenStateSeconds(),
                    defaults.getWaitDurationInOpenStateSeconds())))
        .permittedNumberOfCallsInHalfOpenState(
            resolve(
                props.getPermittedCallsInHalfOpenState(),
                defaults.getPermittedCallsInHalfOpenState()))
        .automaticTransitionFromOpenToHalfOpenEnabled(true)
        .build();
  }

  private <T> T resolve(T override, T defaultValue) {
    return override != null ? override : defaultValue;
  }
}
