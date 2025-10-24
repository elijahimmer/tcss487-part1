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
    final byte[] out = new byte[256 >> 3];

    SHA3SHAKE.SHA3(256, contents, out);

    System.out.printf("%d, %d\n", out[0], out[1]);
    System.out.println(Arrays.toString(out));
  }
}
