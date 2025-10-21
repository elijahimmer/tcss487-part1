public class SHA3SHAKE {
  /**
  * The buffer size in bytes
  */
  private static final int BUFFER_LEN = 200;

  /**
  * The data buffer, must be BUFFER_LEN long
  */
  private final byte[] buffer = null;
  /**
  * The digest length for the output
  */
  private int digest_len;

  public SHA3SHAKE() {}

  /**
  * Initialize the SHA-3/SHAKE sponge.
  * The suffix must be one of 224, 256, 384, or 512 for SHA-3, or one of 128 or 256 for SHAKE.
  * @param suffix SHA-3/SHAKE suffix (SHA-3 digest bitlength = suffix, SHAKE sec level = suffix)
  */
  public void init(int suffix) {
    if (this.buffer != null)
      this.buffer = new byte[BUFFER_LEN];
    assert this.buffer.length == BUFFER_LEN;

    // I think alloc in java zero initializes, but just make sure
    for (int i = 0; i < BUFFER_LEN; i++)
      this.buffer[i] = 0;

    this.digest_len = suffix;
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

    // TODO(Elijah): Don't realloc, generate padding bytes and add them to the buffer
    final byte[] padded = pad(data, pos, len, this.digest_length << 3);
    assert (padded.length % this.digest_length) == 0;

    int i, j;
    for (i = pos; i < len; i += 1) {
      this.buffer[j] ^= data[i];
      j += 1;
      if (j >= this.digest_length) {
        j = 0;
        keccak();
      }
    }
    assert j == 0, "padded message must be a multiple of the digest length";
  }

  /**
  * Update the SHAKE sponge with a byte-oriented data chunk.
  *
  * @param data byte-oriented data buffer
  * @param len byte count on the buffer (starting at index 0)
  */
  public void absorb(byte[] data, int len) {
    abosrb(data, 0, len);
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
  public byte[] squeeze(byte[] out, int len) { /* ... */ }

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
    assert out.length > digestLength();
    // fill out
    return out;
  }

  /**
  * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
  *
  * @return the desired hash value on a newly allocated byte array
  */
  public byte[] digest() {
    final byte[] out = new byte[digestLength];
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
  }

  /**
  * 10*1 pads the input string to a multiple of `x` bits.
  * 
  * @param n The message to pad
  * @param pos initial index to start padding from
  * @param len byte count on the buffer
  * @param x The block size, must be a multiple of 8.
  * @return The padded buffer
  */
  private static byte[] pad(byte[] n, int pos, int len, int x) {
    assert (x & 0b111) == 0; // x must be a multiple of 8.
    final int x_bytes = x >> 3;

    final int bytes_padding = x_bytes - (len % x_bytes);
    assert bytes_padding > 0;

    final int message_length = len + bytes_padding;
    assert (message_length % x_bytes) == 0;

    final byte[] ret = new byte[message_length];
    System.arraycopy(ret, 0,
                     n,   pos,
                     len);

    if (bytes_padding == 1) {
      assert ret.length == len + 1;
      ret[len] = 0b1000_0001;
    } else {
      ret[len] = 0b1000_0000;

      for (int i = len + 1; i < ret.length - 1; i++)
        ret[i] = 0;
      
      ret[ret.length - 1] = 0b000_0001;
    }
  }

  /**
  * Scrambles the buffer using the sha-3 keccak algorithm
  */
  private void keccak() {
    for (int i = 0; i < KECCAK_ROUNDS; i += 1)
      rnd(i);
  };

  /**
  * One round of the sha-3 keccak algorithm
  */
  private void rnd(int index) {
    transformTheta();
    transformRho();
    transformPi();
    transformChi();
    transformIota(index);
  }

  private void transformTheta() {
  }

  private void transformRho() {
  }

  private void transformPi() {
  }

  private void transformChi() {
  }

  private void transformIota(int i) {
  }
}
