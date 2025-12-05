import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Arithmetic on Edwards elliptic curves.
 */
public class Edwards {
  public static final BigInteger p = BigInteger.TWO.pow(256).subtract(BigInteger.valueOf(189));
  public static final BigInteger d = BigInteger.valueOf(15343);
  public static final BigInteger r = BigInteger.TWO.pow(254).subtract(new BigInteger("87175310462106073678594642380840586067"));
  public static final Point G = Point.fromY(BigInteger.valueOf(-4));

  /**
   * Create an instance of the default curve NUMS-256.
   */
  public Edwards() {}

  public static record Key(BigInteger s, Point V) {}

  public static Key getKey(byte[] password) {
    final byte[] out = new byte[48];
    SHA3SHAKE.SHAKE(128, password, out.length, out);

    BigInteger s = (new BigInteger(out)).mod(Edwards.r);
    Point V = Edwards.G.mul(s);

    if (V.x.testBit(0)) {
      s = Edwards.r.subtract(s);
      V = V.negate();
    }

    return new Key(s, V);
  }

  /**
   * Determine if a given affine coordinate pair P = (x, y)
   * defines a point on the curve.
   *
   * @param x x-coordinate of presumed point on the curve
   * @param y y-coordinate of presumed point on the curve
   * @return whether P is really a point on the curve
   */
  public boolean isPoint(BigInteger x, BigInteger y) {
    final BigInteger x2 = x.multiply(x).mod(p);
    final BigInteger y2 = y.multiply(y).mod(p);
    final BigInteger x2y2 = x2.multiply(y2).mod(p);
    final BigInteger sumx2y2 = x2.add(y2).mod(p);
    final BigInteger curveEq = BigInteger.ONE.add(d.multiply(x2y2)).mod(p);

    return sumx2y2.equals(curveEq);
  }

  /**
   * Find a generator G on the curve with the smallest possible
   * y-coordinate in absolute value.
   *
   * @return G.
   */
  public Point gen() {
    return G;
  }

  /**
   * Create a point from its y-coordinate and
   * the least significant bit (LSB) of its x-coordinate.
   *
   * @param y the y-coordinate of the desired point
   * @param x_lsb the LSB of its x-coordinate
   * @return point (x, y) if it exists and has order r,
   * otherwise the neutral element O = (0, 1)
   */
  public Point getPoint(BigInteger y, boolean x_lsb) {
    // TODO(Elijah): finish this
    return new Point();
  }

  /**
   * Display a human-readable representation of this curve.
   *
   * @return a string of form "E: x^2 + y^2 = 1 + d*x^2*y^2 mod p"
   * where E is a suitable curve name (e.g. NUMS ed-256-mers*),
   * d is the actual curve equation coefficient defining this curve,
   * and p is the order of the underlying finite field F_p.
   * TODO(Elijah): Finish this
   */
  public String toString() {
    return "NUMS ed-256-mers*: x^2 + y^2 = 1 + " + d + "*x^2*y^2 mod p";
  }

  /**
   * Edwards curve point in affine coordinates.
   * NB: this is a nested class, enclosed within the Edwards class.
   */
  public static class Point {
    public final BigInteger x;
    public final BigInteger y;

    /**
     * Create a copy of the neutral element on this curve.
     */
    public Point() {
      this.x = BigInteger.ZERO;
      this.y = BigInteger.ONE;
    }

    /**
     * Create a point from its coordinates (assuming
     * these coordinates really define a point on the curve).
     *
     * @param x the x-coordinate of the desired point
     * @param y the y-coordinate of the desired point
     */
    public Point(final BigInteger x, final BigInteger y) {
      this.x = x; this.y = y;
    }

    public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
      assert (p.testBit(0) && p.testBit(1));
      if (v.signum() == 0) {
        return BigInteger.ZERO;
      }
      BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
      if (r.testBit(0) != lsb) {
        r = p.subtract(r);
      }
      return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }


    public static Point fromY(BigInteger y) {
      assert !y.equals(BigInteger.valueOf(-1));
      y = y.mod(p);
      final BigInteger ny2 = y.modPow(BigInteger.TWO, p).negate().mod(p);
      final BigInteger a1 = ny2.add(BigInteger.ONE).mod(p);
      final BigInteger a2 = ny2.multiply(d).add(BigInteger.ONE).mod(p);
      final BigInteger x = sqrt(a1.multiply(a2.modInverse(p)).mod(p), p, true);
      return new Point(x,y);
    }

    /**
     * Determine if this point is the neutral element O on the curve.
     *
     * @return true iff this point is O
     */
    public boolean isZero() {
      return this.x.equals(BigInteger.ZERO) && y.equals(BigInteger.ONE);
    }

    /**
     * Determine if a given point P stands for
     * the same point on the curve as this.
     *
     * @param P a point (presumably on the same curve as this)
     * @return true iff P stands for the same point as this
     */
    public boolean equals(Point P) {
      return this.x.equals(P.x) && this.y.equals(P.y);
    }

    /**
     * Given a point P = (x, y) on the curve,
     * return its opposite -P = (-x, y).
     *
     * @return -P
     */
    public Point negate() {
      return new Point(x.negate().mod(p), y);
    }

    /**
     * Add two given points on the curve, this and P.
     *
     * @param P a point on the curve
     * @return this + P
     */
    public Point add(Point P) {
      final BigInteger x1 = this.x;
      final BigInteger y1 = this.y;
      final BigInteger x2 = P.x;
      final BigInteger y2 = P.y;

      final BigInteger num1 = (x1.multiply(y2)).add(y1.multiply(x2)).mod(p);
      final BigInteger num2 = (y1.multiply(y2)).subtract(x1.multiply(x2)).mod(p);

      final BigInteger denom1 = BigInteger.ONE.add(d.multiply(x1.multiply(x2.multiply(y1.multiply(y2)))));
      final BigInteger denom2 = BigInteger.ONE.subtract(d.multiply(x1.multiply(x2.multiply(y1.multiply(y2)))));
      final BigInteger x3 = num1.multiply(denom1.modInverse(p)).mod(p);
      final BigInteger y3 = num2.multiply(denom2.modInverse(p)).mod(p);

      return new Point(x3, y3);
    }

    /**
     * Multiply a point P = (x, y) on the curve by a scalar m.
     *
     * @param m a scalar factor (an integer mod the curve order)
     * @return m*P
     */
    public Point mul(BigInteger m) {
      m = m.mod(r);
      if (m.signum() == 0) {
        return new Point();
      }
      Point V = new Point();
      Point P = this;

      for (int i = m.bitLength() - 1; i >= 0; i--) {
        V = V.add(V);
        if (m.testBit(i)) {
          V = V.add(P);
        }
      }

      return V;
    }

    /**
     * Display a human-readable representation of this point.
     *
     * @return a string of form "(x, y)" where x and y are
     * the coordinates of this point
     */
    public String toString() {
      return "(" + x + ", " + y + ")";
    }
  }
}
