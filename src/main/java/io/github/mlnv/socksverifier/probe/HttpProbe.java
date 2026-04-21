package io.github.mlnv.socksverifier.probe;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.springframework.stereotype.Component;

@Component
public class HttpProbe {

  public HttpProbeResult probe(Socket socket, URI url, Duration timeout) throws IOException {
    String scheme =
        Objects.requireNonNull(url.getScheme(), "HTTP target must include a URL scheme.");
    return switch (scheme.toLowerCase()) {
      case "http" -> executeRequest(socket, url, timeout);
      case "https" -> executeHttpsRequest(socket, url, timeout);
      default -> throw new IOException("Only http and https URLs are supported.");
    };
  }

  private HttpProbeResult executeHttpsRequest(Socket socket, URI url, Duration timeout)
      throws IOException {
    SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
    SSLSocket sslSocket =
        (SSLSocket) socketFactory.createSocket(socket, url.getHost(), effectivePort(url), true);
    sslSocket.setUseClientMode(true);
    sslSocket.setSoTimeout(Math.toIntExact(timeout.toMillis()));
    sslSocket.startHandshake();
    return executeRequest(sslSocket, url, timeout);
  }

  private HttpProbeResult executeRequest(Socket socket, URI url, Duration timeout)
      throws IOException {
    socket.setSoTimeout(Math.toIntExact(timeout.toMillis()));

    BufferedWriter writer =
        new BufferedWriter(
            new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.ISO_8859_1));
    BufferedReader reader =
        new BufferedReader(
            new InputStreamReader(socket.getInputStream(), StandardCharsets.ISO_8859_1));

    writer.write("GET " + requestPath(url) + " HTTP/1.1\r\n");
    writer.write("Host: " + hostHeader(url) + "\r\n");
    writer.write("User-Agent: socks-verifier/0.0.1\r\n");
    writer.write("Accept: */*\r\n");
    writer.write("Connection: close\r\n\r\n");
    writer.flush();

    String statusLine = reader.readLine();
    if (statusLine == null || statusLine.isBlank()) {
      throw new IOException("The HTTP target did not return a status line.");
    }

    String[] parts = statusLine.split(" ");
    if (parts.length < 2) {
      throw new IOException("The HTTP target returned an invalid status line: " + statusLine);
    }

    int statusCode;
    try {
      statusCode = Integer.parseInt(parts[1]);
    } catch (NumberFormatException ex) {
      throw new IOException(
          "The HTTP target returned a non-numeric status code: " + statusLine, ex);
    }

    while (true) {
      String headerLine = reader.readLine();
      if (headerLine == null || headerLine.isEmpty()) {
        break;
      }
    }

    return new HttpProbeResult(statusCode);
  }

  private String requestPath(URI url) {
    String path = url.getRawPath();
    if (path == null || path.isBlank()) {
      path = "/";
    }
    if (url.getRawQuery() != null && !url.getRawQuery().isBlank()) {
      return path + "?" + url.getRawQuery();
    }
    return path;
  }

  private String hostHeader(URI url) {
    int port = url.getPort();
    String host = Objects.requireNonNull(url.getHost(), "HTTP target must include a host.");
    if (port < 0 || port == 80 || port == 443) {
      return host;
    }
    return host + ":" + port;
  }

  private int effectivePort(URI url) {
    if (url.getPort() > 0) {
      return url.getPort();
    }
    return "https".equalsIgnoreCase(url.getScheme()) ? 443 : 80;
  }
}
