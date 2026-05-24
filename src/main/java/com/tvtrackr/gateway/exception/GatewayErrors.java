package com.tvtrackr.gateway.exception;

import com.tvtrackr.common.error.BusinessErrors;

public class GatewayErrors extends BusinessErrors {

  public static final GatewayErrors UNAUTHORIZED = new GatewayErrors("1000", "Unauthorized", 401);
  public static final GatewayErrors INVALID_TOKEN =
      new GatewayErrors("1001", "Invalid or expired token", 401);
  public static final GatewayErrors MISSING_TOKEN =
      new GatewayErrors("1002", "Authorization token is required", 401);
  public static final GatewayErrors SERVICE_UNAVAILABLE =
      new GatewayErrors("1003", "Service unavailable. Please try again later", 503);

  protected GatewayErrors(String code, String desc, int httpStatus) {
    super(code, desc, httpStatus);
    this.prefix = "GW";
    this.code = prefix + code;
  }
}
