package io.github.mlnv.socksverifier.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import io.github.mlnv.socksverifier.probe.HttpProbe;
import io.github.mlnv.socksverifier.probe.HttpProbeResult;
import io.github.mlnv.socksverifier.socks.Socks5Client;
import io.github.mlnv.socksverifier.support.FakeSocks5Server;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.time.Duration;
import org.junit.jupiter.api.Test;

class DefaultVerificationServiceTest {

  private final DefaultVerificationService verificationService =
      new DefaultVerificationService(new Socks5Client(), new HttpProbe());

  @Test
  void verifiesHttpTargetThroughAuthenticatedSocks5Proxy() throws Exception {
    HttpServer httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    httpServer.createContext("/health", new OkHandler());
    httpServer.start();

    try (FakeSocks5Server fakeSocks5Server = new FakeSocks5Server("demo", "secret")) {
      URI url = URI.create("http://127.0.0.1:" + httpServer.getAddress().getPort() + "/health");
      VerificationRequest request =
          new VerificationRequest(
              "127.0.0.1",
              fakeSocks5Server.port(),
              "demo",
              "secret",
              TargetMode.HTTP,
              url,
              null,
              null,
              Duration.ofSeconds(5));

      VerificationResult result = verificationService.verify(request);

      assertTrue(result.success());
      assertEquals(TargetMode.HTTP, result.targetMode());
      assertEquals(AuthenticationMethod.USERNAME_PASSWORD, result.authenticationMethod());
      assertEquals(AuthenticationStatus.SUCCEEDED, result.authenticationStatus());
      assertEquals(200, result.httpStatus());
      assertEquals(VerificationFailure.NONE, result.failure());
      assertNotNull(result.latencyMillis());
    } finally {
      httpServer.stop(0);
    }
  }

  @Test
  void verifiesTcpTargetThroughAuthenticatedSocks5Proxy() throws Exception {
    try (ServerSocket targetServer = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        FakeSocks5Server fakeSocks5Server = new FakeSocks5Server("demo", "secret")) {
      Thread acceptThread = Thread.ofPlatform().start(() -> acceptOnce(targetServer));

      VerificationRequest request =
          new VerificationRequest(
              "127.0.0.1",
              fakeSocks5Server.port(),
              "demo",
              "secret",
              TargetMode.TCP,
              null,
              "127.0.0.1",
              targetServer.getLocalPort(),
              Duration.ofSeconds(5));

      VerificationResult result = verificationService.verify(request);

      acceptThread.join();
      assertTrue(result.success());
      assertEquals(TargetMode.TCP, result.targetMode());
      assertEquals(AuthenticationMethod.USERNAME_PASSWORD, result.authenticationMethod());
      assertEquals(AuthenticationStatus.SUCCEEDED, result.authenticationStatus());
      assertEquals(VerificationFailure.NONE, result.failure());
      assertNotNull(result.latencyMillis());
    }
  }

  @Test
  void reportsAuthenticationFailureWhenCredentialsAreRejected() throws Exception {
    try (ServerSocket targetServer = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        FakeSocks5Server fakeSocks5Server = new FakeSocks5Server("demo", "secret")) {
      VerificationRequest request =
          new VerificationRequest(
              "127.0.0.1",
              fakeSocks5Server.port(),
              "demo",
              "wrong-password",
              TargetMode.TCP,
              null,
              "127.0.0.1",
              targetServer.getLocalPort(),
              Duration.ofSeconds(5));

      VerificationResult result = verificationService.verify(request);

      assertFalse(result.success());
      assertEquals(AuthenticationMethod.USERNAME_PASSWORD, result.authenticationMethod());
      assertEquals(AuthenticationStatus.FAILED, result.authenticationStatus());
      assertEquals(VerificationFailure.AUTHENTICATION_FAILED, result.failure());
    }
  }

  @Test
  void letsUnexpectedRuntimeExceptionsSurface() {
    DefaultVerificationService service =
        new DefaultVerificationService(
            new Socks5Client() {
              @Override
              public Socket connect(
                  String proxyHost,
                  int proxyPort,
                  String username,
                  String password,
                  String targetHost,
                  int targetPort,
                  Duration timeout) {
                return new Socket();
              }
            },
            new HttpProbe() {
              @Override
              public HttpProbeResult probe(Socket socket, URI url, Duration timeout) {
                throw new IllegalStateException("boom");
              }
            });

    VerificationRequest request =
        new VerificationRequest(
            "127.0.0.1",
            1080,
            "demo",
            "secret",
            TargetMode.HTTP,
            URI.create("http://example.com/health"),
            null,
            null,
            Duration.ofSeconds(5));

    IllegalStateException exception =
        org.junit.jupiter.api.Assertions.assertThrows(
            IllegalStateException.class, () -> service.verify(request));

    assertEquals("boom", exception.getMessage());
  }

  private void acceptOnce(ServerSocket targetServer) {
    try (Socket socket = targetServer.accept()) {
      if (socket.getInputStream().read() < 0) {
        return;
      }
    } catch (IOException ignored) {
    }
  }

  private static final class OkHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
      byte[] body = "ok".getBytes();
      exchange.sendResponseHeaders(200, body.length);
      try (OutputStream outputStream = exchange.getResponseBody()) {
        outputStream.write(body);
      }
    }
  }
}
