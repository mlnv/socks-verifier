package io.github.mlnv.socksverifier.output;

import io.github.mlnv.socksverifier.service.VerificationResult;
import org.springframework.stereotype.Component;

@Component
public class ExitCodeMapper {

  public int toExitCode(VerificationResult result) {
    if (result.success()) {
      return 0;
    }

    return switch (result.failure()) {
      case INVALID_ARGUMENTS -> 2;
      case AUTHENTICATION_FAILED -> 10;
      case PROXY_CONNECTION_FAILED -> 11;
      case TARGET_CONNECTION_FAILED, PROBE_FAILED -> 12;
      case INTERNAL_ERROR -> 13;
      case NONE -> 1;
    };
  }
}
