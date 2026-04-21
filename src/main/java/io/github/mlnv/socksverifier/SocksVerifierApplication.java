package io.github.mlnv.socksverifier;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

@SpringBootApplication
public class SocksVerifierApplication {

  public static void main(String[] args) {
    SpringApplication application = new SpringApplication(SocksVerifierApplication.class);
    application.setWebApplicationType(WebApplicationType.NONE);

    ConfigurableApplicationContext context = application.run(args);
    int exitCode = SpringApplication.exit(context);
    System.exit(exitCode);
  }
}
