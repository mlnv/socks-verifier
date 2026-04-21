package io.github.mlnv.socksverifier.support;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public final class FakeSocks5Server implements AutoCloseable {

  private final String expectedUsername;
  private final String expectedPassword;
  private final ServerSocket serverSocket;
  private final ExecutorService executorService;
  private final AtomicBoolean running;
  private final Thread acceptThread;

  public FakeSocks5Server(String expectedUsername, String expectedPassword) throws IOException {
    this.expectedUsername = expectedUsername;
    this.expectedPassword = expectedPassword;
    this.serverSocket = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
    this.executorService = Executors.newCachedThreadPool();
    this.running = new AtomicBoolean(true);
    this.acceptThread = Thread.ofPlatform().name("fake-socks5-accept").start(this::acceptLoop);
  }

  public int port() {
    return serverSocket.getLocalPort();
  }

  @Override
  public void close() throws Exception {
    running.set(false);
    serverSocket.close();
    acceptThread.join(TimeUnit.SECONDS.toMillis(2));
    executorService.shutdownNow();
    if (!executorService.awaitTermination(2, TimeUnit.SECONDS)) {
      throw new IllegalStateException("Timed out while shutting down the fake SOCKS5 server.");
    }
  }

  private void acceptLoop() {
    while (running.get()) {
      try {
        Socket clientSocket = serverSocket.accept();
        executorService.submit(() -> handleClient(clientSocket));
      } catch (SocketException ex) {
        if (running.get()) {
          throw new IllegalStateException(ex);
        }
        return;
      } catch (IOException ex) {
        throw new IllegalStateException(ex);
      }
    }
  }

  private void handleClient(Socket clientSocket) {
    try (clientSocket) {
      clientSocket.setSoTimeout(5_000);
      InputStream clientInput = clientSocket.getInputStream();
      OutputStream clientOutput = clientSocket.getOutputStream();

      negotiate(clientInput, clientOutput);
      authenticate(clientInput, clientOutput);
      tunnel(clientSocket, clientInput, clientOutput);
    } catch (IOException ignored) {
    }
  }

  private void negotiate(InputStream inputStream, OutputStream outputStream) throws IOException {
    byte[] header = readExactly(inputStream, 2);
    int methodCount = header[1] & 0xFF;
    byte[] methods = readExactly(inputStream, methodCount);
    boolean supportsUsernamePassword = false;
    for (byte method : methods) {
      if ((method & 0xFF) == 0x02) {
        supportsUsernamePassword = true;
        break;
      }
    }

    outputStream.write(new byte[] {0x05, supportsUsernamePassword ? (byte) 0x02 : (byte) 0xFF});
    outputStream.flush();

    if (!supportsUsernamePassword) {
      throw new IOException("Client did not offer username and password authentication.");
    }
  }

  private void authenticate(InputStream inputStream, OutputStream outputStream) throws IOException {
    byte[] authHeader = readExactly(inputStream, 2);
    int usernameLength = authHeader[1] & 0xFF;
    String username = new String(readExactly(inputStream, usernameLength), StandardCharsets.UTF_8);
    int passwordLength = readExactly(inputStream, 1)[0] & 0xFF;
    String password = new String(readExactly(inputStream, passwordLength), StandardCharsets.UTF_8);

    boolean authenticated = expectedUsername.equals(username) && expectedPassword.equals(password);
    outputStream.write(new byte[] {0x01, authenticated ? (byte) 0x00 : (byte) 0x01});
    outputStream.flush();

    if (!authenticated) {
      throw new IOException("Authentication failed.");
    }
  }

  private void tunnel(Socket clientSocket, InputStream clientInput, OutputStream clientOutput)
      throws IOException {
    byte[] requestHeader = readExactly(clientInput, 4);
    int addressType = requestHeader[3] & 0xFF;
    String targetHost = readAddress(clientInput, addressType);
    int targetPort = readPort(clientInput);

    if ((requestHeader[1] & 0xFF) != 0x01) {
      clientOutput.write(new byte[] {0x05, 0x07, 0x00, 0x01, 127, 0, 0, 1, 0, 0});
      clientOutput.flush();
      return;
    }

    try (Socket targetSocket = new Socket()) {
      targetSocket.connect(new InetSocketAddress(targetHost, targetPort), 5_000);
      targetSocket.setSoTimeout(5_000);

      byte[] addressBytes = targetSocket.getLocalAddress().getAddress();
      int replyAddressType = addressBytes.length == 16 ? 0x04 : 0x01;
      int localPort = targetSocket.getLocalPort();

      clientOutput.write(new byte[] {0x05, 0x00, 0x00, (byte) replyAddressType});
      clientOutput.write(addressBytes);
      clientOutput.write((localPort >> 8) & 0xFF);
      clientOutput.write(localPort & 0xFF);
      clientOutput.flush();

      Future<?> upstream = executorService.submit(() -> pipe(clientSocket, targetSocket));
      pipe(targetSocket, clientSocket);
      waitFor(upstream);
    } catch (IOException ex) {
      clientOutput.write(new byte[] {0x05, 0x05, 0x00, 0x01, 127, 0, 0, 1, 0, 0});
      clientOutput.flush();
    }
  }

  private void pipe(Socket sourceSocket, Socket destinationSocket) {
    try {
      InputStream inputStream = sourceSocket.getInputStream();
      OutputStream outputStream = destinationSocket.getOutputStream();
      byte[] buffer = new byte[8_192];
      int read;
      while ((read = inputStream.read(buffer)) >= 0) {
        outputStream.write(buffer, 0, read);
        outputStream.flush();
      }
    } catch (IOException ignored) {
    }
  }

  private void waitFor(Future<?> future) {
    try {
      future.get(2, TimeUnit.SECONDS);
    } catch (Exception ignored) {
    }
  }

  private String readAddress(InputStream inputStream, int addressType) throws IOException {
    return switch (addressType) {
      case 0x01 -> InetAddress.getByAddress(readExactly(inputStream, 4)).getHostAddress();
      case 0x03 ->
          new String(
              readExactly(inputStream, readExactly(inputStream, 1)[0] & 0xFF),
              StandardCharsets.US_ASCII);
      case 0x04 -> InetAddress.getByAddress(readExactly(inputStream, 16)).getHostAddress();
      default -> throw new IOException("Unsupported address type: " + addressType);
    };
  }

  private int readPort(InputStream inputStream) throws IOException {
    byte[] portBytes = readExactly(inputStream, 2);
    return ((portBytes[0] & 0xFF) << 8) | (portBytes[1] & 0xFF);
  }

  private byte[] readExactly(InputStream inputStream, int length) throws IOException {
    byte[] data = new byte[length];
    int offset = 0;
    while (offset < length) {
      int read = inputStream.read(data, offset, length - offset);
      if (read < 0) {
        throw new IOException("Unexpected end of stream.");
      }
      offset += read;
    }
    return data;
  }
}
