package io.github.mlnv.socksverifier;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = "socks-verifier.runner.enabled=false")
class SocksVerifierApplicationTests {

  @Test
  void contextLoads() {}
}
