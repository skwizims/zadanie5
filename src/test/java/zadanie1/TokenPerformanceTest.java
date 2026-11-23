package zadanie1;

import org.junit.jupiter.api.Test;
import zadanie1.security.JwtService;
import zadanie1.security.OpaqueTokenService;
import zadanie1.security.OpaqueTokenStore;
import java.time.Instant;
import java.util.HexFormat;

/** Microbenchmark smoke test: reports average generation + validation time; run repeatedly on same JVM. */
class TokenPerformanceTest {
 private static final String KEY="d09cd0b0d0bad181d0b8d0bcd09cd0b0d0bad181d0b8d0bcd09cd0b0d0bad181";
 @Test void compareJwtAndOpaqueTokenGenerationAndValidation(){
  JwtService jwt=new JwtService(KEY,900,604800); OpaqueTokenService opaque=new OpaqueTokenService(); OpaqueTokenStore store=new OpaqueTokenStore();
  int n=20_000; long start=System.nanoTime();
  for(int i=0;i<n;i++){var a=jwt.createAccess("maksim");jwt.validate(a.token(),"access");}
  long jwtNs=System.nanoTime()-start;
  start=System.nanoTime(); for(int i=0;i<n;i++){String t=opaque.generate();store.put(t,new OpaqueTokenStore.Entry("maksim",Instant.now().plusSeconds(900),"access"));store.getValid(t,"access");} long opaqueNs=System.nanoTime()-start;
  System.out.printf("JWT create+validate avg: %.1f ns; Opaque create+store+lookup avg: %.1f ns%n",(double)jwtNs/n,(double)opaqueNs/n);
 }
}
