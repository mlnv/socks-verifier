package io.github.mlnv.socksverifier.cli;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Component;
import picocli.CommandLine;

@Component
public class CommandVersionProvider implements CommandLine.IVersionProvider {

  private final String version;

  public CommandVersionProvider(ObjectProvider<BuildProperties> buildPropertiesProvider) {
    BuildProperties buildProperties = buildPropertiesProvider.getIfAvailable();
    if (buildProperties != null) {
      this.version = buildProperties.getVersion();
      return;
    }

    Package commandPackage = SocksVerifierCommand.class.getPackage();
    String implementationVersion =
        commandPackage != null ? commandPackage.getImplementationVersion() : null;
    this.version = implementationVersion != null ? implementationVersion : "unknown";
  }

  @Override
  public String[] getVersion() {
    return new String[] {version};
  }
}
