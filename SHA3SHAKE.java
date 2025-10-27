import java.util.Arrays;

public class SHA3SHAKE {
  /**
  * The buffer size in u64s
  */
  private static final int BUFFER_LEN = 25;
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
     && suffix != 256
     && suffix != 384
     && suffix != 512) throw new IllegalArgumentException("Invalid suffix.");

    if (this.buffer == null)
      this.buffer = new long[BUFFER_LEN];
    assert this.buffer.length == BUFFER_LEN;

    // clear buffer if re-used
    for (int i = 0; i < BUFFER_LEN; i++)
      this.buffer[i] = 0;

    this.digest_length = suffix >>> 3;
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
    int rsize = 200 - 2 * this.digest_length;
    for (i = pos; i < len; i += 1) {
      this.buffer[j >>> 3] ^= ((long) data[i]) << (((j & 0b111) << 3));

      j += 1;
      if (j >= rsize) {
        j = 0;
        keccak(this.buffer);
      }
    }

    if (data.length == 0 || j != 0) {
      this.buffer[j >>> 3] ^= 0x06L << (((j & 0b111) << 3));
      this.buffer[(rsize >>> 3) - 1] = (0x80L << 56) | (this.buffer[(rsize >>> 3) - 1] & 0xFF_FF_FF_FF_FF_FF_FFL);

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

    int remaining = len;
    int out_pos = 0;

    while (remaining >= block_len) {
      for (int i = 0; i < block_len; i++) {
        out[i + out_pos] = (byte) ((this.buffer[i >>> 3] >>> (((i & 0b111) << 3))) & 0xFF);
      }
      out_pos += block_len;
      // TODO(Elijah): Uncomment this.
      // keccak(this.buffer);
      remaining -= block_len;
    }

    for (int i = 0; i < remaining; i++) {
      out[i + out_pos] = (byte) ((this.buffer[i >>> 3] >>> (((i & 0b111) << 3))) & 0xFF);
    }

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
    assert out.length == suffix >>> 3;

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
    final int length_bytes = L >>> 3;
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
    1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
  };

  private static final int[] Piln = {
    10, 7, 11, 17, 18,
     3, 5, 16,  8, 21,
    24, 4, 15, 23, 19,
    13, 12, 2, 20, 14,
    22, 9,  6,  1
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
  private static void rnd(final long[] st, final int index) {
    int i, j, r;
    long t;

    // Theta: columns mix
    long[] bc = new long[5];
    for (i = 0; i < 5; i++) {
        bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
    }

    // direction
    for (i = 0; i < 5; i++) {
        t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);

        for (j = 0; j < 25; j += 5)
          st[j + i] ^= t;
    }

    // Rho + Pi
    t = st[1];
    for (i = 0; i < 24; i++) {
        j = Piln[i];
        bc[0] = st[j];
        st[j] = rotl64(t, Rotate[i]);
        t = bc[0];
    }

    //  Chi
    for (j = 0; j < 25; j += 5) {
        for (i = 0; i < 5; i++)
            bc[i] = st[j + i];
        for (i = 0; i < 5; i++)
            st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
    }

    // Iota
    st[0] ^= roundConstants[index];
  }
}
