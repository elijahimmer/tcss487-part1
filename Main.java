import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;

public class Main {
  public static void main(String[] args) throws IOException {
    if (args.length == 0) {
      System.err.println(USAGE);
      System.exit(0);
    }

    switch (args[0]) {
      case "sha3" -> sha3(args);
      case "shake-random" -> shake_random(args);
      case "shake-encrypt" -> shake_encrypt(args);
      default -> {
        System.err.println(USAGE);
        System.exit(1);
      }
    }
  }

  static final String SHA3_USAGE = "usage: sha3shake sha3 <SECURITY_LEVEL_BITS> <FILE>\n";
  static void sha3(String[] args) throws IOException {
    if (args.length != 3) {
        System.err.printf(SHA3_USAGE);
        System.exit(1);
    }

    final int sec = Integer.parseInt(args[1]);
    final String file_name = args[2];

    if (sec != 224
     && sec != 256
     && sec != 384
     && sec != 512) {
      System.err.printf("SECURITY_LEVEL_BITS, must be 224, 256, 384, or 512, found: '%s'", sec);
      System.exit(1);
    }

    final File file = new File(file_name);
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
    System.out.printf(" %s\n", file_name);
  }

  static final String SHAKE_RANDOM_USAGE = "usage: sha3shake shake-random <SECURITY_LEVEL_BITS> <SEED> <LEN>\n";
  static void shake_random(String[] args) {
    if (args.length != 4) {
        System.err.printf(SHAKE_RANDOM_USAGE);
        System.exit(1);
    }

    final int sec = Integer.parseInt(args[1]);
    final String seed = args[2];
    final int len = Integer.parseInt(args[3]);
    final byte[] out = new byte[len];

    if (sec != 128 && sec != 256) {
      System.err.printf("SECURITY_LEVEL_BITS, must be 128 or 256, found: '%s'", sec);
      System.exit(1);
    }

    final SHA3SHAKE sha = new SHA3SHAKE();
    sha.init(sec, true);

    sha.absorb(seed.getBytes());
    sha.squeeze(out, len);

    for (byte b : out) {
      System.out.printf("%02x", b);
    }
  }

  static final String SHAKE_ENCRYPT_USAGE = "usage: sha3shake shake-encrypt <SECURITY_LEVEL_BITS> <KEY> <FILE>\n";
  static void shake_encrypt(String[] args) throws IOException {
    if (args.length != 4) {
        System.err.printf(SHAKE_ENCRYPT_USAGE);
        System.exit(1);
    }

    final int sec = Integer.parseInt(args[1]);
    if (sec != 128 && sec != 256) {
      System.err.printf("SECURITY_LEVEL_BITS, must be 128 or 256, found: '%s'", sec);
      System.exit(1);
    }

    final String key = args[2];
    final String file_name = args[3];

    final File file = new File(file_name);
    final byte[] contents = Files.readAllBytes(file.toPath());

    final byte[] out = new byte[contents.length];

    final SHA3SHAKE sha = new SHA3SHAKE();
    sha.init(sec, true);

    sha.absorb(key.getBytes());
    sha.squeeze(out, out.length);

    for (int i = 0; i < out.length; i++) {
      contents[i] ^= out[i];
    }

    System.out.write(contents);
  }

  static final String EC_KEYGEN_USAGE = "usage: sha3shake ec-keygen [FILE]\n";
  static final String EC_ENCRYPT_USAGE = "usage: sha3shake ec-encrypt <KEY_FILE> <FILE>\n";
  static final String EC_DECRYPT_USAGE = "usage: sha3shake ec-decrypt <KEY_FILE> <FILE>\n";
  static final String EC_SIGN_USAGE = "usage: sha3shake ec-sign <KEY_FILE> <FILE>\n";
  static final String EC_VERIFY_USAGE = "usage: sha3shake ec-verify <KEY_FILE> <FILE>\n";
  static final String USAGE =
        SHA3_USAGE + SHAKE_RANDOM_USAGE + SHAKE_ENCRYPT_USAGE + EC_KEYGEN_USAGE +
        EC_ENCRYPT_USAGE + EC_DECRYPT_USAGE + EC_SIGN_USAGE + EC_VERIFY_USAGE ;
}
