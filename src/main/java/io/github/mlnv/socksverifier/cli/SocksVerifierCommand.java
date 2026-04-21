package io.github.mlnv.socksverifier.cli;

import io.github.mlnv.socksverifier.output.ExitCodeMapper;
import io.github.mlnv.socksverifier.output.ResultFormatter;
import io.github.mlnv.socksverifier.service.AuthenticationStatus;
import io.github.mlnv.socksverifier.service.TargetMode;
import io.github.mlnv.socksverifier.service.VerificationFailure;
import io.github.mlnv.socksverifier.service.VerificationRequest;
import io.github.mlnv.socksverifier.service.VerificationResult;
import io.github.mlnv.socksverifier.service.VerificationService;
import java.io.PrintWriter;
import java.net.URI;
import java.time.Duration;
import java.util.concurrent.Callable;
import org.springframework.stereotype.Component;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

@Component
@Command(
    name = "socks-verifier",
    mixinStandardHelpOptions = true,
    description =
        "Verifies authenticated SOCKS5 proxy connectivity against an HTTP URL or TCP target.")
public class SocksVerifierCommand implements Callable<Integer> {

  private final VerificationService verificationService;
  private final ResultFormatter resultFormatter;
  private final ExitCodeMapper exitCodeMapper;

  @Spec private CommandSpec commandSpec;

  @Option(
      names = "--proxy-host",
      required = true,
      description = "SOCKS5 proxy host name or IP address.")
  private String proxyHost;

  @Option(names = "--proxy-port", required = true, description = "SOCKS5 proxy port.")
  private int proxyPort;

  @Option(names = "--username", required = true, description = "SOCKS5 username.")
  private String username;

  @Option(names = "--password", required = true, description = "SOCKS5 password.")
  private String password;

  @Option(names = "--url", description = "HTTP or HTTPS target URL to probe through the proxy.")
  private URI url;

  @Option(names = "--target-host", description = "TCP target host name or IP address.")
  private String targetHost;

  @Option(names = "--target-port", description = "TCP target port.")
  private Integer targetPort;

  @Option(
      names = "--timeout-ms",
      defaultValue = "10000",
      description = "Connection and probe timeout in milliseconds.")
  private long timeoutMillis = 10_000L;

  @Option(
      names = "--output",
      defaultValue = "TEXT",
      description = "Output format: ${COMPLETION-CANDIDATES}.")
  private OutputFormat outputFormat = OutputFormat.TEXT;

  public SocksVerifierCommand(
      VerificationService verificationService,
      ResultFormatter resultFormatter,
      ExitCodeMapper exitCodeMapper) {
    this.verificationService = verificationService;
    this.resultFormatter = resultFormatter;
    this.exitCodeMapper = exitCodeMapper;
  }

  @Override
  public Integer call() {
    VerificationRequest request;

    try {
      request = toRequest();
    } catch (IllegalArgumentException ex) {
      VerificationResult result =
          VerificationResult.failure(
              currentRequestSnapshot(),
              VerificationFailure.INVALID_ARGUMENTS,
              ex.getMessage(),
              null,
              AuthenticationStatus.NOT_ATTEMPTED);
      writeResult(result);
      return exitCodeMapper.toExitCode(result);
    }

    VerificationResult result = verificationService.verify(request);
    writeResult(result);
    return exitCodeMapper.toExitCode(result);
  }

  private VerificationRequest toRequest() {
    validate();
    return new VerificationRequest(
        proxyHost,
        proxyPort,
        username,
        password,
        url != null ? TargetMode.HTTP : TargetMode.TCP,
        url,
        targetHost,
        targetPort,
        Duration.ofMillis(timeoutMillis));
  }

  private VerificationRequest currentRequestSnapshot() {
    if (!hasText(proxyHost) || proxyPort <= 0 || timeoutMillis <= 0) {
      return null;
    }

    TargetMode mode =
        url != null
            ? TargetMode.HTTP
            : (hasText(targetHost) || targetPort != null ? TargetMode.TCP : null);
    if (mode == null) {
      return null;
    }

    return new VerificationRequest(
        proxyHost,
        proxyPort,
        username,
        password,
        mode,
        url,
        targetHost,
        targetPort,
        Duration.ofMillis(timeoutMillis));
  }

  private void validate() {
    if (!hasText(proxyHost)) {
      throw new IllegalArgumentException("--proxy-host is required.");
    }
    if (!hasText(username)) {
      throw new IllegalArgumentException("--username is required.");
    }
    if (!hasText(password)) {
      throw new IllegalArgumentException("--password is required.");
    }
    if (proxyPort < 1 || proxyPort > 65535) {
      throw new IllegalArgumentException("--proxy-port must be between 1 and 65535.");
    }
    if (timeoutMillis < 1) {
      throw new IllegalArgumentException("--timeout-ms must be greater than zero.");
    }

    boolean hasUrlTarget = url != null;
    boolean hasTcpFields = hasText(targetHost) || targetPort != null;
    if (hasUrlTarget == hasTcpFields) {
      throw new IllegalArgumentException(
          "Provide exactly one target mode: either --url or --target-host with --target-port.");
    }

    if (hasUrlTarget) {
      String scheme = url.getScheme();
      if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
        throw new IllegalArgumentException("--url must use the http or https scheme.");
      }
      if (!hasText(url.getHost())) {
        throw new IllegalArgumentException("--url must include a host.");
      }
      return;
    }

    if (!hasText(targetHost) || targetPort == null) {
      throw new IllegalArgumentException(
          "--target-host and --target-port must be provided together.");
    }
    if (targetPort < 1 || targetPort > 65535) {
      throw new IllegalArgumentException("--target-port must be between 1 and 65535.");
    }
  }

  private void writeResult(VerificationResult result) {
    PrintWriter writer =
        result.success() ? commandSpec.commandLine().getOut() : commandSpec.commandLine().getErr();
    writer.println(resultFormatter.format(result, outputFormat));
    writer.flush();
  }

  private boolean hasText(String value) {
    return value != null && !value.isBlank();
  }
}
