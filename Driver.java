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
    // final byte[] contents = Files.readAllBytes(file.toPath());
    final byte[] contents = new byte[0];
    final int suffix = 224;
    final byte[] out = new byte[suffix >> 3];

    SHA3SHAKE.SHA3(suffix, contents, out);

    for (byte b : out) {
      System.out.printf("%x", b);
    }
    System.out.println(" " + args[0]);
  }
}
