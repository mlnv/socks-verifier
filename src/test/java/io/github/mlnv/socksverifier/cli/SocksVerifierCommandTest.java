package io.github.mlnv.socksverifier.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.mlnv.socksverifier.output.ExitCodeMapper;
import io.github.mlnv.socksverifier.output.ResultFormatter;
import io.github.mlnv.socksverifier.service.VerificationResult;
import io.github.mlnv.socksverifier.service.VerificationService;
import java.io.PrintWriter;
import java.io.StringWriter;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

class SocksVerifierCommandTest {

  @Test
  void rendersJsonForSuccessfulHttpVerification() {
    VerificationService verificationService =
        request ->
            VerificationResult.successHttp(request, 12, 200, "HTTP probe returned status 200.");

    StringWriter output = new StringWriter();
    StringWriter errorOutput = new StringWriter();
    CommandLine commandLine =
        new CommandLine(
            new SocksVerifierCommand(verificationService, formatter(), new ExitCodeMapper()));
    commandLine.setOut(new PrintWriter(output, true));
    commandLine.setErr(new PrintWriter(errorOutput, true));

    int exitCode =
        commandLine.execute(
            "--proxy-host", "127.0.0.1",
            "--proxy-port", "1080",
            "--username", "demo",
            "--password", "secret",
            "--url", "http://example.com/health",
            "--output", "JSON");

    assertEquals(0, exitCode);
    assertTrue(output.toString().contains("\"authenticationMethod\" : \"USERNAME_PASSWORD\""));
    assertTrue(output.toString().contains("\"authenticationStatus\" : \"SUCCEEDED\""));
    assertTrue(output.toString().contains("\"success\" : true"));
    assertTrue(output.toString().contains("\"httpStatus\" : 200"));
    assertTrue(!output.toString().contains("secret"));
    assertEquals("", errorOutput.toString());
  }

  @Test
  void rejectsMixedTargetModes() {
    VerificationService verificationService =
        request -> {
          throw new AssertionError("Verification should not run when arguments are invalid.");
        };

    StringWriter output = new StringWriter();
    StringWriter errorOutput = new StringWriter();
    CommandLine commandLine =
        new CommandLine(
            new SocksVerifierCommand(verificationService, formatter(), new ExitCodeMapper()));
    commandLine.setOut(new PrintWriter(output, true));
    commandLine.setErr(new PrintWriter(errorOutput, true));

    int exitCode =
        commandLine.execute(
            "--proxy-host", "127.0.0.1",
            "--proxy-port", "1080",
            "--username", "demo",
            "--password", "secret",
            "--url", "http://example.com/health",
            "--target-host", "example.com",
            "--target-port", "443");

    assertEquals(2, exitCode);
    assertTrue(errorOutput.toString().contains("Authentication: USERNAME_PASSWORD"));
    assertTrue(errorOutput.toString().contains("Authentication status: NOT_ATTEMPTED"));
    assertTrue(errorOutput.toString().contains("Provide exactly one target mode"));
    assertTrue(!errorOutput.toString().contains("secret"));
    assertEquals("", output.toString());
  }

  @Test
  void letsUnexpectedVerificationExceptionsSurface() {
    VerificationService verificationService =
        request -> {
          throw new IllegalStateException("boom");
        };

    StringWriter output = new StringWriter();
    StringWriter errorOutput = new StringWriter();
    CommandLine commandLine =
        new CommandLine(
            new SocksVerifierCommand(verificationService, formatter(), new ExitCodeMapper()));
    commandLine.setOut(new PrintWriter(output, true));
    commandLine.setErr(new PrintWriter(errorOutput, true));

    int exitCode =
        commandLine.execute(
            "--proxy-host", "127.0.0.1",
            "--proxy-port", "1080",
            "--username", "demo",
            "--password", "secret",
            "--url", "http://example.com/health");

    assertEquals(1, exitCode);
    assertTrue(errorOutput.toString().contains("IllegalStateException: boom"));
    assertTrue(!errorOutput.toString().contains("Authentication status:"));
    assertEquals("", output.toString());
  }

  private ResultFormatter formatter() {
    ObjectMapper objectMapper =
        new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .enable(SerializationFeature.INDENT_OUTPUT);
    return new ResultFormatter(objectMapper);
  }
}
