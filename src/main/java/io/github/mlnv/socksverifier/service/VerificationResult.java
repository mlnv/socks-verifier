package io.github.mlnv.socksverifier.service;

import java.time.Instant;

public record VerificationResult(
    boolean success,
    TargetMode targetMode,
    String proxyHost,
    Integer proxyPort,
    String target,
    AuthenticationMethod authenticationMethod,
    AuthenticationStatus authenticationStatus,
    Long latencyMillis,
    Integer httpStatus,
    VerificationFailure failure,
    String message,
    Instant verifiedAt) {

  public static VerificationResult success(
      VerificationRequest request, long latencyMillis, String message) {
    return new VerificationResult(
        true,
        request.targetMode(),
        request.proxyHost(),
        request.proxyPort(),
        request.targetDescription(),
        request.authenticationMethod(),
        AuthenticationStatus.SUCCEEDED,
        latencyMillis,
        null,
        VerificationFailure.NONE,
        message,
        Instant.now());
  }

  public static VerificationResult successHttp(
      VerificationRequest request, long latencyMillis, int httpStatus, String message) {
    return new VerificationResult(
        true,
        request.targetMode(),
        request.proxyHost(),
        request.proxyPort(),
        request.targetDescription(),
        request.authenticationMethod(),
        AuthenticationStatus.SUCCEEDED,
        latencyMillis,
        httpStatus,
        VerificationFailure.NONE,
        message,
        Instant.now());
  }

  public static VerificationResult failure(
      VerificationRequest request,
      VerificationFailure failure,
      String message,
      Long latencyMillis,
      AuthenticationStatus authenticationStatus) {
    return new VerificationResult(
        false,
        request != null ? request.targetMode() : null,
        request != null ? request.proxyHost() : null,
        request != null ? request.proxyPort() : null,
        request != null ? request.targetDescription() : null,
        request != null ? request.authenticationMethod() : null,
        authenticationStatus,
        latencyMillis,
        null,
        failure,
        message,
        Instant.now());
  }
}
