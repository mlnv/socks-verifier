package io.github.mlnv.socksverifier.output;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.mlnv.socksverifier.cli.OutputFormat;
import io.github.mlnv.socksverifier.service.VerificationResult;
import org.springframework.stereotype.Component;

@Component
public class ResultFormatter {

  private final ObjectMapper objectMapper;

  public ResultFormatter(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  public String format(VerificationResult result, OutputFormat outputFormat) {
    return switch (outputFormat) {
      case JSON -> formatJson(result);
      case TEXT -> formatText(result);
    };
  }

  private String formatJson(VerificationResult result) {
    try {
      return objectMapper.writeValueAsString(result);
    } catch (JsonProcessingException ex) {
      throw new IllegalStateException("Unable to render verification result as JSON.", ex);
    }
  }

  private String formatText(VerificationResult result) {
    StringBuilder builder = new StringBuilder();
    builder.append(result.success() ? "SUCCESS" : "FAILURE").append(System.lineSeparator());

    if (result.failure() != null && !result.success()) {
      builder.append("Failure: ").append(result.failure()).append(System.lineSeparator());
    }
    if (result.targetMode() != null) {
      builder.append("Mode: ").append(result.targetMode()).append(System.lineSeparator());
    }
    if (result.proxyHost() != null && result.proxyPort() != null) {
      builder
          .append("Proxy: ")
          .append(result.proxyHost())
          .append(":")
          .append(result.proxyPort())
          .append(System.lineSeparator());
    }
    if (result.target() != null) {
      builder.append("Target: ").append(result.target()).append(System.lineSeparator());
    }
    if (result.authenticationMethod() != null) {
      builder
          .append("Authentication: ")
          .append(result.authenticationMethod())
          .append(System.lineSeparator());
    }
    if (result.authenticationStatus() != null) {
      builder
          .append("Authentication status: ")
          .append(result.authenticationStatus())
          .append(System.lineSeparator());
    }
    if (result.httpStatus() != null) {
      builder.append("HTTP status: ").append(result.httpStatus()).append(System.lineSeparator());
    }
    if (result.latencyMillis() != null) {
      builder.append("Latency ms: ").append(result.latencyMillis()).append(System.lineSeparator());
    }
    if (result.message() != null && !result.message().isBlank()) {
      builder.append("Message: ").append(result.message()).append(System.lineSeparator());
    }
    if (result.verifiedAt() != null) {
      builder.append("Verified at: ").append(result.verifiedAt()).append(System.lineSeparator());
    }

    return builder.toString().stripTrailing();
  }
}
