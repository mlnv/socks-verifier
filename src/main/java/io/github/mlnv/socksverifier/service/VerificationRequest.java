package io.github.mlnv.socksverifier.service;

import java.net.URI;
import java.time.Duration;

public record VerificationRequest(
    String proxyHost,
    int proxyPort,
    String username,
    String password,
    TargetMode targetMode,
    URI url,
    String targetHost,
    Integer targetPort,
    Duration timeout) {

  public AuthenticationMethod authenticationMethod() {
    return AuthenticationMethod.USERNAME_PASSWORD;
  }

  public String targetDescription() {
    return targetMode == TargetMode.HTTP ? url.toString() : targetHost + ":" + targetPort;
  }

  public String effectiveTargetHost() {
    if (targetMode == TargetMode.HTTP) {
      return url.getHost();
    }
    return targetHost;
  }

  public int effectiveTargetPort() {
    if (targetMode == TargetMode.HTTP) {
      if (url.getPort() > 0) {
        return url.getPort();
      }
      return "https".equalsIgnoreCase(url.getScheme()) ? 443 : 80;
    }
    return targetPort;
  }
}
