package io.github.mlnv.socksverifier.service;

import io.github.mlnv.socksverifier.probe.HttpProbe;
import io.github.mlnv.socksverifier.probe.HttpProbeResult;
import io.github.mlnv.socksverifier.socks.Socks5Client;
import io.github.mlnv.socksverifier.socks.SocksException;
import java.io.IOException;
import java.net.Socket;
import org.springframework.stereotype.Service;

@Service
public class DefaultVerificationService implements VerificationService {

  private final Socks5Client socks5Client;
  private final HttpProbe httpProbe;

  public DefaultVerificationService(Socks5Client socks5Client, HttpProbe httpProbe) {
    this.socks5Client = socks5Client;
    this.httpProbe = httpProbe;
  }

  @Override
  public VerificationResult verify(VerificationRequest request) {
    long startedAt = System.nanoTime();

    try (Socket socket =
        socks5Client.connect(
            request.proxyHost(),
            request.proxyPort(),
            request.username(),
            request.password(),
            request.effectiveTargetHost(),
            request.effectiveTargetPort(),
            request.timeout())) {
      if (request.targetMode() == TargetMode.TCP) {
        return VerificationResult.success(
            request,
            elapsedMillis(startedAt),
            "TCP connection established through the SOCKS5 proxy.");
      }

      HttpProbeResult httpProbeResult = httpProbe.probe(socket, request.url(), request.timeout());
      return VerificationResult.successHttp(
          request,
          elapsedMillis(startedAt),
          httpProbeResult.statusCode(),
          "HTTP probe returned status " + httpProbeResult.statusCode() + ".");
    } catch (SocksException ex) {
      return VerificationResult.failure(
          request,
          ex.failure(),
          ex.getMessage(),
          elapsedMillis(startedAt),
          ex.authenticationStatus());
    } catch (IOException ex) {
      VerificationFailure failure =
          request.targetMode() == TargetMode.HTTP
              ? VerificationFailure.PROBE_FAILED
              : VerificationFailure.TARGET_CONNECTION_FAILED;
      return VerificationResult.failure(
          request,
          failure,
          defaultMessage(ex),
          elapsedMillis(startedAt),
          AuthenticationStatus.SUCCEEDED);
    }
  }

  private long elapsedMillis(long startedAt) {
    return (System.nanoTime() - startedAt) / 1_000_000;
  }

  private String defaultMessage(Exception ex) {
    if (ex.getMessage() == null || ex.getMessage().isBlank()) {
      return ex.getClass().getSimpleName();
    }
    return ex.getMessage();
  }
}
