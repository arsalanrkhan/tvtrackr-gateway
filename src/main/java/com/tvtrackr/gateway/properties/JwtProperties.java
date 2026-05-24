package com.tvtrackr.gateway.properties;

import jakarta.annotation.PostConstruct;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Loads the RSA public key once at startup from the JWT_PUBLIC_KEY environment variable.
 *
 * <p>Key rotation requires a gateway restart. The industry-standard alternative is a JWKS endpoint
 * on auth-service (GET /api/auth/v1/.well-known/jwks.json) with periodic cache refresh — deferred
 * as a future improvement since key rotation is not a current requirement.
 */
@Component
@ConfigurationProperties(prefix = "app.jwt")
public class JwtProperties {

  @Setter private String publicKey;
  @Getter private RSAPublicKey rsaPublicKey;

  @PostConstruct
  public void init() {
    try {
      byte[] publicDecoded = Base64.getDecoder().decode(publicKey);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      this.rsaPublicKey = (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(publicDecoded));
    } catch (Exception e) {
      throw new IllegalStateException("Failed to load RSA public key", e);
    }
  }
}
