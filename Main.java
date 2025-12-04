import java.io.File;
import java.io.FileWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.util.Arrays;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;
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
      case "ec-keygen" -> ec_keygen(args);
      case "ec-encrypt" -> ec_encrypt(args);
      case "ec-decrypt" -> ec_decrypt(args);
      case "ec-sign" -> ec_sign(args);
      case "ec-verify" -> ec_verify(args);
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

    final byte[] out = new byte[sec >> 3];

    SHA3SHAKE.SHA3(sec, contents, out);

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
    final byte[] seed = args[2].getBytes();
    final int len = Integer.parseInt(args[3]);
    final byte[] out = new byte[len];

    if (sec != 128 && sec != 256) {
      System.err.printf("SECURITY_LEVEL_BITS, must be 128 or 256, found: '%s'", sec);
      System.exit(1);
    }

    SHA3SHAKE.SHAKE(sec, seed, out.length, out);

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

    SHA3SHAKE.SHAKE(sec,key.getBytes(), contents.length, out);

    for (int i = 0; i < out.length; i++) {
      contents[i] ^= out[i];
    }

    System.out.write(contents);
  }

  static final String EC_KEYGEN_USAGE = "usage: sha3shake ec-keygen <PASSWORD> <KEY_FILE>\n";
  static void ec_keygen(String[] args) throws IOException {
    if (args.length != 3) {
      System.err.printf(EC_KEYGEN_USAGE);
      System.exit(1);
    }

    final String password = args[1];
    final String private_file_name = args[2];
    final String public_file_name = args[2] + ".pub";

    final var private_file = new PrintWriter(private_file_name);
    final var public_file = new PrintWriter(public_file_name);

    final Edwards.Key key = Edwards.getKey(password.getBytes());
    final BigInteger s = key.s();
    System.out.println("Private key s: " + s);
    {
      final byte[] bytes = key.s().toByteArray();
      for (int i = 0; i < bytes.length; i++) {
        private_file.printf("%02x", bytes[i]);
      }
      private_file.println();
      private_file.flush();
    }

    {
      byte[] bytes = key.V().x.toByteArray();
      for (int i = 0; i < bytes.length; i++) {
        public_file.printf("%02x", bytes[i]);
      }
      public_file.println();

      bytes = key.V().y.toByteArray();
      for (int i = 0; i < bytes.length; i++) {
        public_file.printf("%02x", bytes[i]);
      }
      public_file.println();
      public_file.flush();
    }
  }

  static final String EC_ENCRYPT_USAGE = "usage: sha3shake ec-encrypt <KEY_FILE> <FILE>\n";
  static void ec_encrypt(String[] args) throws IOException {
    if (args.length != 3) {
      System.err.printf(EC_ENCRYPT_USAGE);
      System.exit(1);
    }

    final File public_key_file = new File(args[1] + ".pub");
    final byte[] public_key = Files.readAllBytes(public_key_file.toPath());

    final var output_file = new FileWriter(args[2] + ".bin");
  }

  static final String EC_DECRYPT_USAGE = "usage: sha3shake ec-decrypt <KEY_FILE> <FILE>\n";
  static void ec_decrypt(String[] args) {
    if (args.length != 3) {
      System.err.printf(EC_DECRYPT_USAGE);
      System.exit(1);
    }
  }

  static final String EC_SIGN_USAGE = "usage: sha3shake ec-sign <PASSWORD> <FILE>\n";
  static void ec_sign(String[] args) throws IOException {
    if (args.length != 3) {
      System.err.printf(EC_SIGN_USAGE);
      System.exit(1);
    }

    final String password = args[1];
    final String file_name = args[2];

    final File file = new File(file_name);
    final byte[] message = Files.readAllBytes(file.toPath());
    final Edwards.Key key = Edwards.getKey(password.getBytes());
    final BigInteger s = key.s();
    System.out.println("Private key s: " + s);

    final SecureRandom secRand = new SecureRandom();
    final byte[] randBytes = new byte[48];
    secRand.nextBytes(randBytes);

    final BigInteger k = new BigInteger(randBytes).mod(Edwards.r);
    Edwards.Point U = Edwards.G.mul(k);
    final byte[] Uy = U.y.toByteArray();

    final SHA3SHAKE sha256 = new SHA3SHAKE();
    sha256.init(256);
    sha256.absorb(Uy);
    sha256.absorb(message);
    final byte[] digest = sha256.digest();

    final BigInteger h = new BigInteger(digest).mod(Edwards.r);
    final BigInteger z = k.subtract(h.multiply(s)).mod(Edwards.r);

    System.out.println(h);
    System.out.println(z);
  }

  static final String EC_VERIFY_USAGE = "usage: sha3shake ec-verify <PUB_KEY_FILE> <SIGNATURE_FILE> <FILE>\n";
  static void ec_verify(String[] args) throws IOException {
    if (args.length != 4) {
      System.err.printf(EC_VERIFY_USAGE);
      System.exit(1);
    }
    final String pub_key_file = args[1];
    final String sig_file = args[2];
    final String message_file = args[3];

    final File file = new File(message_file);
    final byte[] message = Files.readAllBytes(file.toPath());

    Scanner scanner = new Scanner(new File(pub_key_file));
    BigInteger x = new BigInteger(scanner.nextLine(), 16);
    BigInteger y = new BigInteger(scanner.nextLine(), 16);

    final Edwards.Point V = new Edwards.Point(x, y);
    scanner.close();

    final Scanner scanTwo = new Scanner(new File(sig_file));
    final BigInteger h = new BigInteger(scanTwo.nextLine());
    final BigInteger z = new BigInteger(scanTwo.nextLine());
    scanTwo.close();
    final Edwards.Point Ui = (Edwards.G.mul(z)).add(V.mul(h));

    final byte[] Uiy = Ui.y.toByteArray();

    final SHA3SHAKE sha256 = new SHA3SHAKE();
    sha256.init(256);
    sha256.absorb(Uiy);
    sha256.absorb(message);
    final byte[] digest = sha256.digest();
    final BigInteger hi = new BigInteger(digest).mod(Edwards.r);
    System.out.println(h);
    System.out.println(hi);

    if (hi.equals(h)) {
      System.out.println("VERIFIED");
    } else {
      System.out.println("Unverified");
    }

  }

  static final String USAGE =
        SHA3_USAGE + SHAKE_RANDOM_USAGE + SHAKE_ENCRYPT_USAGE + EC_KEYGEN_USAGE +
        EC_ENCRYPT_USAGE + EC_DECRYPT_USAGE + EC_SIGN_USAGE + EC_VERIFY_USAGE;
}
