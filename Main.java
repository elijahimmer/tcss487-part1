import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;

public class Main {
  public static void main(String[] args) throws IOException {
    if (args.length != 2) {
      System.err.println("usage: sha3shake <SECURITY_LEVEL_BITS> <FILE>");
      System.exit(1);
    }

    int sec = Integer.parseInt(args[0]);

    if (sec != 128
     && sec != 224
     && sec != 256
     && sec != 384
     && sec != 512) {
      System.err.printf("SECURITY_LEVEL_BITS, must be 128, 224, 256, 384, or 512, found: '%s'", args[0]);
      System.exit(1);
    }

    final File file = new File(args[1]);
    final byte[] contents = Files.readAllBytes(file.toPath());

    final int suffix = sec;
    final byte[] out = new byte[suffix >> 3];

    final SHA3SHAKE sha = new SHA3SHAKE();
    sha.init(suffix);

    sha.absorb(contents);
    sha.digest(out);

    for (byte b : out) {
      System.out.printf("%02x", b);
    }
    System.out.printf(" %s\n", args[1]);
  }
}
