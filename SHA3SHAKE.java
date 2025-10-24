import java.util.Arrays;

public class SHA3SHAKE {
  /**
  * The buffer size in u64s
  */
  private static final int BUFFER_LEN = 25;
  /**
  * The buffer size in longs
  */
  private static final int LONG_BUFFER_LEN = 25;
  /**
   * 24 rounds in the Keccak function
   */
  private static final int KECCAK_ROUNDS = 24;
  /**
  * The data buffer, must be BUFFER_LEN long
  */
  private long[] buffer = null;
  /**
  * The digest length for the output in bytes
  */
  private int digest_length;

  public SHA3SHAKE() {}

  /**
  * Initialize the SHA-3/SHAKE sponge.
  * The suffix must be one of 224, 256, 384, or 512 for SHA-3, or one of 128 or 256 for SHAKE.
  * @param suffix SHA-3/SHAKE suffix (SHA-3 digest bitlength = suffix, SHAKE sec level = suffix)
  */
  public void init(int suffix) {
    if (suffix != 128
     && suffix != 224
     && suffix != 256
     && suffix != 384
     && suffix != 512) throw new IllegalArgumentException("Invalid suffix");

    if (this.buffer == null)
      this.buffer = new long[BUFFER_LEN];
    assert this.buffer.length == BUFFER_LEN;

    // clear buffer if re-used
    for (int i = 0; i < BUFFER_LEN; i++)
      this.buffer[i] = 0;

    this.digest_length = suffix >> 3;
  }

  /**
  * Update the SHAKE sponge with a byte-oriented data chunk.
  *
  * @param data byte-oriented data buffer
  * @param pos initial index to hash from
  * @param len byte count on the buffer
  */
  public void absorb(byte[] data, int pos, int len) {
    assert data != null;
    assert this.buffer != null;

    int i, j = 0;
    for (i = pos; i < len; i += 1) {
      this.buffer[j >> 3] ^= data[i] << ((j & 0b111) << 3);
      j += 1;
      if (j >= this.digest_length) {
        j = 0;
        keccak(this.buffer);
      }
    }

    if (j + 1 != this.digest_length) {
      this.buffer[j >> 3] ^= 0b1000_0000 << ((j & 0b111) << 3);
      this.buffer[(this.digest_length >> 3) - 1] ^= 0b0000_0001;

      keccak(this.buffer);
    }
  }

  /**
  * Update the SHAKE sponge with a byte-oriented data chunk.
  *
  * @param data byte-oriented data buffer
  * @param len byte count on the buffer (starting at index 0)
  */
  public void absorb(byte[] data, int len) {
    absorb(data, 0, len);
  }

  /**
  * Update the SHAKE sponge with a byte-oriented data chunk.
  *
  * @param data byte-oriented data buffer
  */
  public void absorb(byte[] data) {
    absorb(data, 0, data.length);
  }

  /**
  * Squeeze a chunk of hashed bytes from the sponge.
  * Call this method as many times as needed to extract the total desired number of bytes.
  *
  * @param out hash value buffer
  * @param len desired number of squeezed bytes
  * @return the val buffer containing the desired hash value
  */
  public byte[] squeeze(final byte[] out, final int len) {
    assert out.length >= len;
    final int block_len = this.digest_length;

    System.err.println("State: " + Arrays.toString(this.buffer));

    int remaining = len;
    int out_pos = 0;

    while (remaining >= block_len) {
      for (int i = 0; i < block_len; i++) {
        out[i + out_pos] = (byte) ((this.buffer[i >> 3] >> ((i & 0b111) << 3)) & 0xFF);
      }
      out_pos += block_len;
      keccak(this.buffer);
      remaining -= block_len;
    }

    for (int i = 0; i < remaining; i++) {
      out[i + out_pos] = (byte) ((this.buffer[i >> 3] >> ((i & 0b111) << 3)) & 0xFF);
    }

    System.err.println("Array: " + Arrays.toString(out));

    return out;
  }

  /**
  * Squeeze a chunk of hashed bytes from the sponge.
  * Call this method as many times as needed to extract the total desired number of bytes.
  *
  * @param len desired number of squeezed bytes
  * @return newly allocated buffer containing the desired hash value
  */
  public byte[] squeeze(int len) {
    final byte[] out = new byte[len];
    squeeze(out, len);
    return out;
  }

  /**
  * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
  *
  * NOTE(Elijah): Not sure what this is
  *
  * @param out hash value buffer
  * @return the val buffer containing the desired hash value
  */
  public byte[] digest(byte[] out) {
    assert out.length == this.digest_length;
    squeeze(out, this.digest_length);
    return out;
  }

  /**
  * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
  *
  * @return the desired hash value on a newly allocated byte array
  */
  public byte[] digest() {
    final byte[] out = new byte[this.digest_length];
    return digest(out);
  }

  /**
  * Compute the streamlined SHA-3-<224,256,384,512> on input X.
  *
  * @param suffix desired output length in bits (one of 224, 256, 384, 512)
  * @param X data to be hashed
  * @param out hash value buffer (if null, this method allocates it with the required size)
  * @return the out buffer containing the desired hash value.
  */
  public static byte[] SHA3(int suffix, byte[] X, byte[] out) {
    assert out.length == suffix >> 3;

    final SHA3SHAKE sha = new SHA3SHAKE();
    sha.init(suffix);

    sha.absorb(X);
    sha.digest(out);
    return out;
  }

  /**
  * Compute the streamlined SHAKE-<128,256> on input X with output bitlength L.
  *
  * @param suffix desired security level (either 128 or 256)
  * @param X data to be hashed
  * @param L desired output length in bits (must be a multiple of 8)
  * @param out hash value buffer (if null, this method allocates it with the required size)
  * @return the out buffer containing the desired hash value.
  */
  public static byte[] SHAKE(int suffix, byte[] X, int L, byte[] out) {
    final int length_bytes = L >> 3;
    assert out.length >= length_bytes;

    final SHA3SHAKE sha = new SHA3SHAKE();
    sha.init(suffix);

    sha.absorb(X);
    sha.squeeze(out, length_bytes);

    return out;
  }

  /**
  * Scrambles the buffer using the sha-3 keccak algorithm
  */
  private static void keccak(long[] input) {
    assert input.length == BUFFER_LEN;

    // Run algorithm
    for (int i = 0; i < KECCAK_ROUNDS; i += 1)
      rnd(input, i);
  }

    /**
     * Round constants for Keccak-f[1600], width = 64
     */
  private static final long[] roundConstants = {
          0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L,
          0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
          0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
          0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L, 0x8000000000008003L,
          0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL,
          0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
  };

    /**
     * Rotating Offset for Rho
     */
  private static final int[] Rotate = {
           0, 36,  3, 41, 18,
           1, 44, 10, 45,  2,
          62,  6, 43, 15, 61,
          28, 55, 25, 21, 56,
          27, 20, 39,  8,  14
  };
  /**
   * Helper method for rotl64
   * @param x 64-bit value to rotate
   * @param y bits rotate left
   * @return x rotate left by y bits
   */
  private static long rotl64(long x, int y) {
      return (x << y) | (x >>> (64 - y));
  }
  /**
  * One round of the sha-3 keccak algorithm
  */
  private static void rnd(long[] data, int index) {
    // Theta: columns mix
      long[] C = new long[5];
      for (int i = 0; i < 5; i++) {
          C[i] = data[i] ^ data[i + 5] ^ data[i + 10] ^ data[i + 15] ^ data[i + 20];
      }
      // direction
      long[] D = new long[5];
      for (int x = 0; x < 5; x++) {
          D[x] = rotl64(C[(x + 1) % 5], 1) ^ C[(x + 4) % 5];
      }
      for (int y = 0; y < 5; y++) {
          int row = 5 * y;
          data[row + 0] ^= D[0];
          data[row + 1] ^= D[1];
          data[row + 2] ^= D[2];
          data[row + 3] ^= D[3];
          data[row + 4] ^= D[4];
      }
    // Rho + Pi
      long[] B = new long[25];
      for (byte y = 0; y < 5; y++) {
          for (int x = 0; x < 5; x++) {
              // source lane index
              int src = 5 * y + x;
              // x prime
              int xp = y;
              //y prime
              int yp = (2 * x + 3 * y) % 5;
              // x', y' in 5x5 grid
              int dst = 5 * yp + xp;
              // rho rotation
              B[dst] = rotl64(data[src], Rotate[src]);
          }
      }
    // Chi
      for (int y = 0; y < 5; y++) {
//          long[] st = new long[5];
//          for (int x = 0; x < 5; x++) {
//              st[x] = data[y + x];
//          }
//          for (int x = 0; x < 5; x++) {
//              data[y + x] = st[x] ^ ((~st[(x + 1) % 5]) & st[(x + 2) % 5]);
//          }
          // This is more efficient.
          // start index of rows
          int st = 5 * y;
          // b0-4 = A[x,y] because we are working in the B array we don't need to apply z.
          long b0 = B[st + 0];
          long b1 = B[st + 1];
          long b2 = B[st + 2];
          long b3 = B[st + 3];
          long b4 = B[st + 4];
          // Output A'
          data[st + 0] = b0 ^ ((~b1) & b2);
          data[st + 1] = b1 ^ ((~b2) & b3);
          data[st + 2] = b2 ^ ((~b3) & b4);
          data[st + 3] = b3 ^ ((~b4) & b0);
          data[st + 4] = b4 ^ ((~b0) & b1);

      }
    // Iota
      data[0] ^= roundConstants[index];
  }
}
