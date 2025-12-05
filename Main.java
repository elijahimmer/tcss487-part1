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
    // Base name, and message file.
    final String key_base = args[1];
    final String msg_file_name = args[2];

    // Read public key file.
    final File public_key_file = new File(args[1] + ".pub");
    final byte[] public_key = Files.readAllBytes(public_key_file.toPath());
    final String public_key_string = new String(public_key);

    // First line x, second line y.
    final String[] lines = public_key_string.split("\\R");
    if (lines.length < 2) {
        System.err.printf("Invalid key file.");
        System.exit(1);
    }

    BigInteger Vx = new BigInteger(lines[0], 16);
    BigInteger Vy = new BigInteger(lines[1], 16);

    // V from y and LSB of x using the curve.
    final Edwards curve = new Edwards();
    final boolean x_lsb = Vx.testBit(0);
    final Edwards.Point V = curve.getPoint(Vy, x_lsb);

    final File msg_file = new File(msg_file_name);
    final byte[] m = Files.readAllBytes(msg_file.toPath());

    // Random 384-bit k
    final byte[] k_bytes = new byte[48]; // 384 bits.
    new SecureRandom().nextBytes(k_bytes);
    BigInteger k = new BigInteger(1, k_bytes).mod(Edwards.r);

    // W = kV, Z = kG
    final Edwards.Point W = V.mul(k);
    final Edwards.Point Z = Edwards.G.mul(k);

    // SHAKE convert contents to byte array.
    final byte[] Wy = W.y.toByteArray();
    final byte[] shake_output = new byte[64];
    SHA3SHAKE.SHAKE(256, Wy, shake_output.length << 3, shake_output);

    final byte[] ka = new byte[32];
    final byte[] ke = new byte[32];
    for (int i = 0; i < 32; i++) {
        ka[i] = shake_output[i];
        ke[i] = shake_output[32 + i];
    }

    // SHAKE on ke, m bytes, XOR with m to get c.
    final byte[] ke_stream = new byte[m.length];
    SHA3SHAKE.SHAKE(128, ke, ke_stream.length << 3, ke_stream);

    final byte[] c = new byte[m.length];
    for (int i = 0; i < m.length; i++) {
        c[i] = (byte) (m[i] ^ ke_stream[i]);
    }

    //SHA3-256, absorb ka and then c, extract digest t.
    final byte[] mac_input = new byte[ka.length + c.length];
    System.arraycopy(ka, 0, mac_input, 0, ka.length);
    System.arraycopy(c, 0, mac_input, ka.length, c.length);

    final byte[] t = new byte[32];
    SHA3SHAKE.SHA3(256, mac_input, t);

    // (Z,c,t) to FILE.bin as hex
    try (FileWriter fw = new FileWriter(msg_file_name + ".bin");
         PrintWriter out = new PrintWriter(fw)) {

        out.println(Z.x.toString(16));
        out.println(Z.y.toString(16));

        for (int i = 0; i < t.length; i++) {
            out.printf("%02x", t[i]);
        }
        out.println();

        for(int i = 0; i < c.length; i++) {
            out.printf("%02x", c[i]);
        }
        out.println();
    }
  }

  static final String EC_DECRYPT_USAGE = "usage: sha3shake ec-decrypt <KEY_FILE> <FILE>\n";
  static void ec_decrypt(String[] args) throws IOException {
    if (args.length != 3) {
      System.err.printf(EC_DECRYPT_USAGE);
      System.exit(1);
    }
      // Private key file, ciphertext file.
      final String key_file_name = args[1];
      final String cipher_file_name = args[2];

      // Reads private scalar s from key file.
      final File private_file = new File(key_file_name);
      final byte[] private_byte = Files.readAllBytes(private_file.toPath());
      final String private_string = new String(private_byte);
      final String[] private_lines = private_string.split("\\R");
      if (private_lines.length < 1) {
          System.err.println("Invalid private key.");
          System.exit(1);
      }
      BigInteger s = new BigInteger(private_lines[0], 32).mod(Edwards.r);

      // Reads ciphertext
      final File cipher_file = new File(cipher_file_name);
      final byte[] cipher_bytes = Files.readAllBytes(cipher_file.toPath());
      final String cipher_string = new String(cipher_bytes);
      final String[] lines = cipher_string.split("\\R");
      if (lines.length < 4) {
          System.err.println("Invalid ciphertext.");
          System.exit(1);
      }
      // Zx Zy
      final BigInteger Zx = new BigInteger(lines[0], 16);
      final BigInteger Zy = new BigInteger(lines[1], 16);

      //t to byte[]
      final String t_hex = lines[2];
      final int t_len = t_hex.length() / 2;
      final byte[] t = new byte[t_len];
      for (int i = 0; i < t_len; i++) {
          int high = Character.digit(t_hex.charAt(2 * i), 16);
          int low = Character.digit(t_hex.charAt(2 * i + 1), 16);
          t[i] = (byte) ((high << 4) | low);
      }

      //c to byte[]
      final String c_hex = lines[3];
      final int c_len = c_hex.length() / 2;
      final byte[] c = new byte[c_len];
      for (int i = 0; i < c_len; i++) {
          int high = Character.digit(c_hex.charAt(2 * i), 16);
          int low = Character.digit(c_hex.charAt(2 * i + 1), 16);
          c[i] = (byte) ((high << 4) | low);
      }
      // Z from Zy and LSB of Zx
      final Edwards curve = new Edwards();
      final boolean Z_x_lsb = Zx.testBit(0);
      final Edwards.Point Z = curve.getPoint(Zy, Z_x_lsb);

      // W = sZ
      final Edwards.Point W = Z.mul(s);

      //SHAKE256 on y-coord of W to ka || ke
      final byte[] Wy = W.y.toByteArray();
      final byte[] shake_output = new byte[64]; // 512 bits
      SHA3SHAKE.SHAKE(256, Wy, shake_output.length << 3, shake_output);

      final byte[] ka = new byte[32];
      final byte[] ke = new byte[32];
      for (int i = 0; i < 32; i++) {
          ka[i] = shake_output[i];
          ke[i] = shake_output[32 + i];
      }
      // t' ka || c
      final byte[] mac_input = new byte[ka.length + c.length];
      System.arraycopy(ka, 0, mac_input, 0, ka.length);
      System.arraycopy(c, 0, mac_input, ka.length, c.length);

      final byte[] tprime = new byte[32];
      SHA3SHAKE.SHA3(256, mac_input, tprime);

      // t = t' ?
      boolean work = (tprime.length == t.length);
      for (int i = 0; work && i < t.length; i++) {
          if (tprime[i] != t[i]) {
              work = false;
          }
      }
      if (!work) {
          System.err.println("Decryption error, authentication mismatch.");
          System.exit(1);
      }

      // SHAKE on ke to c bytes, XOR with c to get m
      final byte[] ke_stream = new byte[c.length];
      SHA3SHAKE.SHAKE(128, ke, ke_stream.length << 3, ke_stream);

      final byte[] m = new byte[c.length];
      for (int i = 0; i < c.length; i++) {
          m[i] = (byte) (c[i] ^ ke_stream[i]);
      }

      System.out.write(m);
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

    final SecureRandom secRand = new SecureRandom();
    final byte[] randBytes = new byte[48];
    secRand.nextBytes(randBytes);

    final BigInteger kRaw = new BigInteger(randBytes);
    final BigInteger k = kRaw.mod(Edwards.r);

    final Edwards.Point U = Edwards.G.mul(k);

    final BigInteger h;
    {
      final SHA3SHAKE sha256 = new SHA3SHAKE();
      sha256.init(256, false);
      sha256.absorb(U.y.toByteArray());
      sha256.absorb(message);
      final byte[] digest = sha256.digest();
      assert digest.length == 32;
      h = new BigInteger(digest).mod(Edwards.r);
    }

    final BigInteger z = k.subtract(h.multiply(s).mod(Edwards.r)).mod(Edwards.r);

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

    final byte[] message = Files.readAllBytes(new File(message_file).toPath());

    final Edwards.Point V;
    {
      final Scanner scanner = new Scanner(new File(pub_key_file));
      final BigInteger x = new BigInteger(scanner.next(), 16);
      final BigInteger y = new BigInteger(scanner.next(), 16);

      V = new Edwards.Point(x, y);

      scanner.close();
    }

    final Edwards.Point UPrime;
    final BigInteger h;
    {
      final Scanner scanTwo = new Scanner(new File(sig_file));
      h = new BigInteger(scanTwo.next());
      final BigInteger z = new BigInteger(scanTwo.next());
      scanTwo.close();
      UPrime = Edwards.G.mul(z).add(V.mul(h));
    }

    final BigInteger hPrime;
    {
      final SHA3SHAKE sha256 = new SHA3SHAKE();
      sha256.init(256, false);
      sha256.absorb(UPrime.y.toByteArray());
      sha256.absorb(message);
      final byte[] digest = sha256.digest();

      hPrime = new BigInteger(digest).mod(Edwards.r);
    }

    if (hPrime.equals(h)) {
      System.out.println("VERIFIED");
    } else {
      System.out.println("INVALID SIGNATURE!");
    }
  }

  static final String USAGE =
        SHA3_USAGE + SHAKE_RANDOM_USAGE + SHAKE_ENCRYPT_USAGE + EC_KEYGEN_USAGE +
        EC_ENCRYPT_USAGE + EC_DECRYPT_USAGE + EC_SIGN_USAGE + EC_VERIFY_USAGE;

  // { // test maths
  //   assert Edwards.G.mul(BigInteger.ZERO).equals(new Edwards.Point());
  //   assert Edwards.G.mul(BigInteger.ONE).equals(Edwards.G);
  //   assert Edwards.G.add(Edwards.G.negate()).equals(new Edwards.Point());
  //   assert Edwards.G.mul(BigInteger.TWO).equals(Edwards.G.add(Edwards.G));
  //   assert !Edwards.G.mul(BigInteger.valueOf(4)).equals(new Edwards.Point());
  //   assert Edwards.G.mul(Edwards.r).equals(new Edwards.Point());

  //   final SecureRandom secRand = new SecureRandom();
  //   final byte[] randBytes = new byte[48];

  //   secRand.nextBytes(randBytes);
  //   final BigInteger k = new BigInteger(randBytes);
  //   secRand.nextBytes(randBytes);
  //   final BigInteger l = new BigInteger(randBytes);
  //   secRand.nextBytes(randBytes);
  //   final BigInteger m = new BigInteger(randBytes);

  //   assert Edwards.G.mul(k).equals(Edwards.G.mul(k.mod(Edwards.r)));
  //   assert Edwards.G.mul(k.add(BigInteger.ONE).mod(Edwards.r)).equals(Edwards.G.add(Edwards.G.mul(k)));
  //   assert Edwards.G.mul(l).mul(k).equals(Edwards.G.mul(k).mul(l));
  //   assert Edwards.G.mul(l).mul(k).equals(Edwards.G.mul(k).mul(l.mod(Edwards.r)));
  //   assert Edwards.G.mul(k).add(Edwards.G.mul(l).add(Edwards.G.mul(m))).equals(Edwards.G.mul(m).add(Edwards.G.mul(l).add(Edwards.G.mul(k))));
  // }
}
