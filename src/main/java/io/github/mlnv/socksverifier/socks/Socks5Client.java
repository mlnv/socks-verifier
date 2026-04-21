package io.github.mlnv.socksverifier.socks;

import io.github.mlnv.socksverifier.service.AuthenticationStatus;
import io.github.mlnv.socksverifier.service.VerificationFailure;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.IDN;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.springframework.stereotype.Component;

@Component
public class Socks5Client {

  private static final int SOCKS_VERSION = 0x05;
  private static final int USERNAME_PASSWORD_AUTH = 0x02;
  private static final int CONNECT_COMMAND = 0x01;
  private static final int DOMAIN_NAME_TYPE = 0x03;
  private static final int AUTH_VERSION = 0x01;

  public Socket connect(
      String proxyHost,
      int proxyPort,
      String username,
      String password,
      String targetHost,
      int targetPort,
      Duration timeout)
      throws IOException {
    Socket socket = new Socket();
    int timeoutMillis = Math.toIntExact(timeout.toMillis());
    AuthenticationStatus authenticationStatus = AuthenticationStatus.NOT_ATTEMPTED;

    try {
      socket.connect(new InetSocketAddress(proxyHost, proxyPort), timeoutMillis);
      socket.setSoTimeout(timeoutMillis);

      InputStream inputStream = socket.getInputStream();
      OutputStream outputStream = socket.getOutputStream();

      negotiateAuthentication(outputStream, inputStream);
      performUsernamePasswordAuthentication(outputStream, inputStream, username, password);
      authenticationStatus = AuthenticationStatus.SUCCEEDED;
      openConnectTunnel(outputStream, inputStream, targetHost, targetPort);
      return socket;
    } catch (IOException ex) {
      try {
        socket.close();
      } catch (IOException ignored) {
      }

      if (ex instanceof SocksException socksException) {
        throw socksException;
      }
      throw new SocksException(
          VerificationFailure.PROXY_CONNECTION_FAILED,
          "Unable to connect to SOCKS5 proxy: " + ex.getMessage(),
          ex,
          authenticationStatus);
    }
  }

  private void negotiateAuthentication(OutputStream outputStream, InputStream inputStream)
      throws IOException {
    outputStream.write(new byte[] {SOCKS_VERSION, 0x01, USERNAME_PASSWORD_AUTH});
    outputStream.flush();

    byte[] response = readExactly(inputStream, 2, AuthenticationStatus.NOT_ATTEMPTED);
    if (response[0] != SOCKS_VERSION) {
      throw new SocksException(
          VerificationFailure.PROXY_CONNECTION_FAILED,
          "Proxy returned an unsupported SOCKS version during negotiation.",
          AuthenticationStatus.NOT_ATTEMPTED);
    }
    if ((response[1] & 0xFF) == 0xFF) {
      throw new SocksException(
          VerificationFailure.AUTHENTICATION_FAILED,
          "Proxy does not accept username and password authentication.",
          AuthenticationStatus.NOT_ATTEMPTED);
    }
    if ((response[1] & 0xFF) != USERNAME_PASSWORD_AUTH) {
      throw new SocksException(
          VerificationFailure.AUTHENTICATION_FAILED,
          "Proxy selected an unexpected authentication method.",
          AuthenticationStatus.NOT_ATTEMPTED);
    }
  }

  private void performUsernamePasswordAuthentication(
      OutputStream outputStream, InputStream inputStream, String username, String password)
      throws IOException {
    byte[] usernameBytes = username.getBytes(StandardCharsets.UTF_8);
    byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);

    if (usernameBytes.length == 0 || usernameBytes.length > 255) {
      throw new SocksException(
          VerificationFailure.INVALID_ARGUMENTS,
          "Username must contain between 1 and 255 UTF-8 bytes.",
          AuthenticationStatus.NOT_ATTEMPTED);
    }
    if (passwordBytes.length == 0 || passwordBytes.length > 255) {
      throw new SocksException(
          VerificationFailure.INVALID_ARGUMENTS,
          "Password must contain between 1 and 255 UTF-8 bytes.",
          AuthenticationStatus.NOT_ATTEMPTED);
    }

    outputStream.write(AUTH_VERSION);
    outputStream.write(usernameBytes.length);
    outputStream.write(usernameBytes);
    outputStream.write(passwordBytes.length);
    outputStream.write(passwordBytes);
    outputStream.flush();

    byte[] response = readExactly(inputStream, 2, AuthenticationStatus.FAILED);
    if (response[0] != AUTH_VERSION) {
      throw new SocksException(
          VerificationFailure.AUTHENTICATION_FAILED,
          "Proxy returned an invalid username and password authentication response.",
          AuthenticationStatus.FAILED);
    }
    if (response[1] != 0x00) {
      throw new SocksException(
          VerificationFailure.AUTHENTICATION_FAILED,
          "SOCKS5 authentication failed for the supplied username and password.",
          AuthenticationStatus.FAILED);
    }
  }

  private void openConnectTunnel(
      OutputStream outputStream, InputStream inputStream, String targetHost, int targetPort)
      throws IOException {
    String asciiHost = IDN.toASCII(targetHost);
    byte[] hostBytes = asciiHost.getBytes(StandardCharsets.US_ASCII);

    if (hostBytes.length == 0 || hostBytes.length > 255) {
      throw new SocksException(
          VerificationFailure.INVALID_ARGUMENTS,
          "Target host must contain between 1 and 255 ASCII bytes.",
          AuthenticationStatus.SUCCEEDED);
    }

    outputStream.write(SOCKS_VERSION);
    outputStream.write(CONNECT_COMMAND);
    outputStream.write(0x00);
    outputStream.write(DOMAIN_NAME_TYPE);
    outputStream.write(hostBytes.length);
    outputStream.write(hostBytes);
    outputStream.write((targetPort >> 8) & 0xFF);
    outputStream.write(targetPort & 0xFF);
    outputStream.flush();

    byte[] header = readExactly(inputStream, 4, AuthenticationStatus.SUCCEEDED);
    if (header[0] != SOCKS_VERSION) {
      throw new SocksException(
          VerificationFailure.PROXY_CONNECTION_FAILED,
          "Proxy returned an unsupported SOCKS version for the CONNECT response.",
          AuthenticationStatus.SUCCEEDED);
    }

    int replyCode = header[1] & 0xFF;
    int addressType = header[3] & 0xFF;
    consumeBoundAddress(inputStream, addressType);
    readExactly(inputStream, 2, AuthenticationStatus.SUCCEEDED);

    if (replyCode != 0x00) {
      throw new SocksException(
          VerificationFailure.TARGET_CONNECTION_FAILED,
          mapReplyCode(replyCode),
          AuthenticationStatus.SUCCEEDED);
    }
  }

  private void consumeBoundAddress(InputStream inputStream, int addressType) throws IOException {
    switch (addressType) {
      case 0x01 -> readExactly(inputStream, 4, AuthenticationStatus.SUCCEEDED);
      case 0x03 -> {
        int length = readExactly(inputStream, 1, AuthenticationStatus.SUCCEEDED)[0] & 0xFF;
        readExactly(inputStream, length, AuthenticationStatus.SUCCEEDED);
      }
      case 0x04 -> readExactly(inputStream, 16, AuthenticationStatus.SUCCEEDED);
      default ->
          throw new SocksException(
              VerificationFailure.PROXY_CONNECTION_FAILED,
              "Proxy returned an unsupported bound address type.",
              AuthenticationStatus.SUCCEEDED);
    }
  }

  private String mapReplyCode(int replyCode) {
    return switch (replyCode) {
      case 0x01 -> "General SOCKS5 server failure while connecting to the target.";
      case 0x02 -> "SOCKS5 proxy ruleset rejected the target connection.";
      case 0x03 -> "Network unreachable while connecting through the SOCKS5 proxy.";
      case 0x04 -> "Host unreachable while connecting through the SOCKS5 proxy.";
      case 0x05 -> "Connection refused by the target through the SOCKS5 proxy.";
      case 0x06 -> "TTL expired while connecting through the SOCKS5 proxy.";
      case 0x07 -> "SOCKS5 proxy does not support the CONNECT command.";
      case 0x08 -> "SOCKS5 proxy does not support the requested address type.";
      default -> "SOCKS5 proxy returned reply code " + replyCode + ".";
    };
  }

  private byte[] readExactly(
      InputStream inputStream, int length, AuthenticationStatus authenticationStatus)
      throws IOException {
    byte[] data = new byte[length];
    int offset = 0;
    while (offset < length) {
      int read = inputStream.read(data, offset, length - offset);
      if (read < 0) {
        throw new SocksException(
            VerificationFailure.PROXY_CONNECTION_FAILED,
            "Unexpected end of stream while reading the SOCKS5 proxy response.",
            authenticationStatus);
      }
      offset += read;
    }
    return data;
  }
}
