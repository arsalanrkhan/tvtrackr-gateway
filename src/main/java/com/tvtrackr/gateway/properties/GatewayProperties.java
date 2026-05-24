package com.tvtrackr.gateway.properties;

import java.util.List;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "app.gateway")
public class GatewayProperties {
  private List<String> publicRoutes;
}
