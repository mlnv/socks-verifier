package io.github.mlnv.socksverifier.cli;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.ExitCodeGenerator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import picocli.CommandLine;

@Component
@ConditionalOnProperty(
    name = "socks-verifier.runner.enabled",
    havingValue = "true",
    matchIfMissing = true)
public class SocksVerifierRunner implements ApplicationRunner, ExitCodeGenerator {

  private final SocksVerifierCommand socksVerifierCommand;
  private final CommandVersionProvider commandVersionProvider;
  private int exitCode;

  public SocksVerifierRunner(
      SocksVerifierCommand socksVerifierCommand, CommandVersionProvider commandVersionProvider) {
    this.socksVerifierCommand = socksVerifierCommand;
    this.commandVersionProvider = commandVersionProvider;
  }

  @Override
  public void run(ApplicationArguments args) {
    CommandLine commandLine = new CommandLine(socksVerifierCommand);
    commandLine.setCaseInsensitiveEnumValuesAllowed(true);
    commandLine.getCommandSpec().versionProvider(commandVersionProvider);
    exitCode = commandLine.execute(args.getSourceArgs());
  }

  @Override
  public int getExitCode() {
    return exitCode;
  }
}
