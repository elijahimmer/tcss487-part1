import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;

public class Driver {
  public static void main(String[] args) throws IOException {
    if (args.length != 1) {
      System.err.println("usage: sha3shake <FILE>");
      System.exit(1);
    }

    final File file = new File(args[0]);
    final byte[] contents = Files.readAllBytes(file.toPath());
    final int suffix = 224;
    final byte[] out = new byte[suffix >> 3];

    final SHA3SHAKE sha = new SHA3SHAKE();
    sha.init(suffix);

    sha.absorb(contents);
    sha.digest(out);

    for (byte b : out) {
      System.out.printf("%02X", b);
    }
    System.out.printf(" %s\n", args[0]);
  }
}
