import java.math.BigInteger;

/**
 * <h1>DHE</h1>
 * <p>This class implements a basic form of the original Diffie-Hellman key exchange protocol.</p>
 */
public class DHE {

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ///  VARIABLES                                                                                                         ///
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /**
     * <h3>generator</h3>
     * <p>Member variable for the generator parameter.</p>
     */
    private BigInteger generator;

    /**
     * <h3>prime</h3>
     * <p>Member variable for the prime parameter.</p>
     */
    private BigInteger prime;

    /**
     * <h3>privateKey</h3>
     * <p>Our private key.</p>
     * <p><b>Do not leave this public</b></p>
     */
    private BigInteger privateKey;

    public String name;


    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ///  CONSTRUCTORS                                                                                                      ///
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
     
    /**
     * <h3>DHE Constructor</h3>
     * <p>The constructor for the DHE class.</p>
     * <p>Accepts int values gBits and pBits to specify the bit widths of the relevant parameters.</p>
     * <p>These values should be generated securely using the methods provided in the Crypto class and stored in the corresponding member variables.</p>
     * @param gBits The number of bits (bit width) to target for the generator
     * @param pBits The number of bits to target for the prime modulus
     * @param name The name of the DHE instance (for debugging purposes) Represents the name of the two parties making the exchange
     */
    public DHE(int gBits, int pBits, String name) {
        // TODO
        // Convert gBits -> generator
        // Convert pBits -> prime
        this.prime = Crypto.getPrime(pBits, pBits, 10);
        this.generator = Crypto.getGenerator(gBits, prime);
        Tools.debugLog("(" + name + ") - Prime and generator generated!");
        this.privateKey = this.getBase(2048, name);
        this.name = name;
    }

    /**
     * <h3>DHE Constructor</h3>
     * <p>The constructor for the DHE class.</p>
     * <p>Accepts int values gBits and pBits to specify the bit widths of the relevant parameters.</p>
     * <p>These values should be generated securely using the methods provided in the Crypto class and stored in the corresponding member variables.</p>
     * @param g The generator
     * @param p The prime modulus
     * @param name The name of the DHE instance (for debugging purposes) Represents the name of the two parties making the exchange
     */
    public DHE(BigInteger g, BigInteger p, String name) {
        this.prime = p;
        this.generator = g;
        Tools.debugLog("(" + name +") - Initialized with agreed public g and p!");
        this.privateKey = this.getBase(2048, name);
        this.name = name;

    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ///  FUNCTIONS                                                                                                         ///
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /**
     * <h3>getBase</h3>
     * <p>Accepts an int specifying the target bit width for a base (a, b, etc) and returns a valid base.</p>
     * @param bits The number of bits to target for the base
     * @return The generated base value
     */
    public BigInteger getBase(int bits, String name) {
        Tools.debugLog("(" + name + ") - Generating a private key of " + bits + " bits...");
        return Crypto.getRandom(bits, bits);
    }

    public BigInteger getPublicKey() {
        Tools.debugLog("(" + name + ") - Providing my public key...");
        Tools.debugLog("(" + name + ") - Generating public key using my private key and public generator/prime...");
        Tools.debugLog("Calculating public key with g^a mod p...");
        BigInteger publicKey = this.generator.modPow(this.privateKey, this.prime);

        return publicKey;
    }

    public BigInteger getCommonKey(BigInteger publicKey) {
        Tools.debugLog("(" + name + ") - Generating common key using my private key and the other party's public key...");
        Tools.debugLog("Calculating common key with A^b mod p...");
        BigInteger commonKey = publicKey.modPow(this.privateKey, this.prime);
        Tools.debugLog("(" + name + ") - Common key is a shared secret!");
        return commonKey;
    }

    /**
     * <h3>main</h3>
     * <p><b>For testing purposes only.</b></p>
     * <p>Final submission should be a <b>safe</b> class implementation</p>
     */
    public static void main(String[] args) {

        DHE Bob = new DHE(512, 2048, "Bob");
        DHE Alice = new DHE(Bob.generator, Bob.prime, "Alice");

        System.out.println("\nAlice's private key: " + Alice.privateKey);
        System.out.println("\nBob's private key: " + Bob.privateKey);

        BigInteger A = Alice.getPublicKey();
        BigInteger B = Bob.getPublicKey();

        System.out.println("\nAlice's public key: " + A);
        System.out.println("\nBob's public key: " + B);

        BigInteger commonKeyAlice = Alice.getCommonKey(B);
        BigInteger commonKeyBob = Bob.getCommonKey(A);

        System.out.println("\nAlice's common key: " + commonKeyAlice);
        System.out.println("\nBob's common key: " + commonKeyBob);

        

        // DHE d = new DHE(512, 2048);
        // System.out.printf("g = %s%np = %s%n%n", d.generator, d.prime);
        // BigInteger a = d.getBase(512);
        // BigInteger b = d.getBase(512);
        // System.out.printf("a = %s%nb = %s%n%n", a, b);
        // Tools.debugLog("Calculating A and B...");
        // BigInteger A = d.getExponent(a);
        // BigInteger B = d.getExponent(b);
        // System.out.printf("A = %s%nB = %s%n%n", A, B);
        // Tools.debugLog("Calculating key 1 using private key a and public key B...");
        // BigInteger aKey = d.getKey(a, B);
        // Tools.debugLog("Calculating key 2 using private key b and public key A...");
        // BigInteger bKey = d.getKey(b, A);
        // System.out.printf("key 1 = %s%n%nkey 2 = %s%n", aKey, bKey);

        // DHE e = new DHE(512, 2048);
        // System.out.printf("g = %s%np = %s%n%n", d.generator, d.prime);
        // BigInteger x = e.getBase(512);
        // BigInteger y = e.getBase(512);
        // BigInteger z = e.getBase(512);
        // System.out.printf("x = %s%ny = %s%nz = %s%n%n", x, y, z);
        // BigInteger X = e.getExponent(x);
        // BigInteger Y = e.getExponent(y);
        // BigInteger Z = e.getExponent(z);
        // System.out.printf("X = %s%nY = %s%nZ = %s%n%n", X, Y, Z);
        // BigInteger xKey = e.getKey(x, e.getKey(y, Z));
        // BigInteger yKey = e.getKey(y, e.getKey(z, X));
        // BigInteger zKey = e.getKey(z, e.getKey(x, Y));
        // System.out.printf("keys = %s%n%s%n%s%n", xKey, yKey, zKey);
    }
}
