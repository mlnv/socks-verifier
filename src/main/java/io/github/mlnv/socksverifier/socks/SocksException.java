package io.github.mlnv.socksverifier.socks;

import io.github.mlnv.socksverifier.service.AuthenticationStatus;
import io.github.mlnv.socksverifier.service.VerificationFailure;
import java.io.IOException;

public class SocksException extends IOException {

  private final VerificationFailure failure;
  private final AuthenticationStatus authenticationStatus;

  public SocksException(
      VerificationFailure failure, String message, AuthenticationStatus authenticationStatus) {
    super(message);
    this.failure = failure;
    this.authenticationStatus = authenticationStatus;
  }

  public SocksException(
      VerificationFailure failure,
      String message,
      Throwable cause,
      AuthenticationStatus authenticationStatus) {
    super(message, cause);
    this.failure = failure;
    this.authenticationStatus = authenticationStatus;
  }

  public VerificationFailure failure() {
    return failure;
  }

  public AuthenticationStatus authenticationStatus() {
    return authenticationStatus;
  }
}
