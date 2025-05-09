import java.math.BigInteger;
import java.nio.charset.Charset;

/**
 * <h1>RSA</h1>
 * <p>This class implements a basic form of the RSA asymmetric encryption and digital signing system.</p>
 */
public class RSA {

    // p, q, n, phi(n), e, d
    // p, q = prime
    // n = pq
    // phi(n) = euler's totient = (p-1)(q-1)
    // e = any number that's coprime to phi(n), 1 < e < phi(n)
    // d = e^-1 mod phi(n)
    // ed mod phi = 1


    // To encrypt: M = m
    // plaintext = ciphertext^d mod n
    // m < n
    /**
     * <h3>p</h3>
     * <p>One of the two primes used to generate n</p>
     * <p><b>Do not leave this public</b></p>
     */
    private BigInteger p;
    // TODO

    /**
     * <h3>q</h3>
     * <p>One of the two primes used to generate n</p>
     * <p><b>Do not leave this public</b></p>
     */
    private BigInteger q;
    // TODO

    /**
     * <h3>phi</h3>
     * <p>The result of (p-1)(q-1)</p>
     * <p><b>Do not leave this public</b></p>
     */
    private BigInteger phi;
    // TODO

    /**
     * <h3>n</h3>
     * <p>The result of p*q</p>
     */
    private BigInteger n;

    /**
     * <h3>e</h3>
     * <p>Any number which is co-prime with n and one of two values (along with n) which make up the public key.</p>
     */
    private BigInteger e;

    /**
     * <h3>d</h3>
     * <p>The modular inverse of e and one of two values (along with n) which make up the private key.</p>
     * <p><b>Do not leave this public</b></p>
     */
    private BigInteger d;
    // TODO

    /**
     * <h3>RSA Constructor</h3>
     * <p>The constructor for the RSA class.</p>
     * <p>Accepts an int value indicating the desired bit width of the p and q parameters.</p>
     * <p>Generates random p and q, then from those derives n and phi</p>
     * @param bits The number of bits (bit width) desired for the p and q values.
     */
    public RSA(int bits) {
        // TODO
        System.out.println("Generating keys...");
        p = BigInteger.probablePrime(bits, Rand.getRand());
        q = BigInteger.probablePrime(bits, Rand.getRand());
        n = p.multiply(q);
        phi = (p.subtract(BigInteger.ONE)).multiply((q.subtract(BigInteger.ONE))); // Euler's totient = (p-1)(q-1)
        e = Crypto.coprime(phi);
        d = e.modInverse(phi);
        verifyKeys(p, q, phi, n, d);
    }

    /**
     * <h3>getPubKey</h3>
     * <p>A simple getter method for the public key.</p>
     * @return An array of BigInteger containing e and n.
     */
    public BigInteger[] getPubKey() {
        return new BigInteger[] {e, n};
    }

    /**
     * <h3>encrypt</h3>
     * <p>Accepts a message String and a public key and returns the encrypted message.</p>
     * <p>ciphertext = m^e mod n <p>
     * @param message A String containing a message (signed or in plaintext)
     * @param pubKey An array of BigInteger containing a public key [e, n].
     * @return The result of encrypting the message using the given public key.
     */
    public String encrypt(String message, BigInteger[] pubKey) {
        // TODO
        BigInteger encoded = checkMessage(message);
        BigInteger cipher = encoded.modPow(pubKey[0], pubKey[1]);
        return cipher.toString();
    }

    /**
     * <h3>decrypt</h3>
     * <p>Accepts a ciphertext and uses the private key stored in the member variables to decrypt.</p>
     * @param ciphertext A String containing an encryptedd message.
     * @return The result of decrypting the message using the private key [d, n].
     */
    public String decrypt(String ciphertext) {
        // TODO
        BigInteger m = checkMessage(ciphertext);
        BigInteger plain = m.modPow(d, n);
        return new String(plain.toByteArray(), Charset.forName("UTF-8"));
    }

    /**
     * <h3>sign</h3>
     * <p>Accepts a message String and cryptographically signs the message using the private key stored in the member variables [d, n].</p>
     * @param message A String containing a message to be signed.
     * @return The result of encrypting the message using the private key [d, n].
     */
    public String sign(String message) {
        // TODO
        BigInteger s = checkMessage(message);
        BigInteger result = s.modPow(d, n);
        return result.toString();
    }

    /**
     * <h3>authenticate</h3>
     * <p>Accepts a signed (encrypted) message and a public key and uses the given public key to decrypt the message.</p>
     * @param message A String containing a signed message.
     * @param pubKey An array of BigInteger containing a public key [e, n].
     * @return The result of decrypting the message using the given public key.
     */
    public String authenticate(String message, BigInteger[] pubKey) {
        // TODO
        BigInteger v = checkMessage(message);
        BigInteger plain = v.modPow(pubKey[0], pubKey[1]);
        return new String(plain.toByteArray(), Charset.forName("UTF-8"));
    }

    // This method is used if an empty string is passed as the message to encrypt
    // Gets around a no value error from the BigInteger class
    private BigInteger checkMessage(String message) {
        if(message.equals("")) {
            return BigInteger.valueOf(0);
        }

        BigInteger m = new BigInteger(message.getBytes(Charset.forName("UTF-8")));

        return m;
    }

    // Testing the relationship between each key and making sure they're valid
    private void verifyKeys(BigInteger p, BigInteger q, BigInteger phi, BigInteger n, BigInteger d) {
        boolean isValid = true;
        int numChecks = 10;
        if(!Crypto.checkPrime(p, numChecks) || !Crypto.checkPrime(q, 10)) {
            System.out.println("Either p or q are not prime numbers");
            isValid = false;
        }

        
        if(!n.equals(p.multiply(q))) {
            System.out.println("N is not p*q");
            isValid = false;
        }

        if(!phi.equals((p.subtract(BigInteger.ONE)).multiply((q.subtract(BigInteger.ONE))))) {
            System.out.println("Phi is not equal to (p-1)(q-1)");
            isValid = false;
        }

        if((n.min(phi)).equals(n)) {
            System.out.println("n <= phi");
            isValid = false;
        }

        if(e.min(phi).equals(phi)) {
            System.out.println("e >= phi");
            isValid = false;
        }

        if(!(Crypto.gcd(e, phi).equals(BigInteger.ONE))) {
            System.out.println("e is not coprime to phi");
            isValid = false;
        }

        // Testing e and d
        BigInteger ed = e.multiply(d);

        if(!((e.multiply(d)).mod(phi)).equals(BigInteger.ONE) ) {
            System.out.println("d, and e dont fit the identify of ed === 1 (mod phi)");
            isValid = false;
        }

        if(n.bitLength() < 2048) {
            System.out.println("n is less than 2048 bits");
        }

        if(isValid) {
            System.out.println("All tests passed! Keys are valid");
        }

        System.out.println();
    }

    /**
     * <h3>main</h3>
     * <p><b>For testing purposes only.</b></p>
     * <p>Final submission should be a <b>safe</b> class implementation.</p>
     */
    public static void main(String[] args) {
        RSA a = new RSA(4096);
        BigInteger[] aPub = a.getPubKey();
        System.out.printf("p = %s%nq = %s%nn = %s%nphi = %s%ne = %s%nd = %s%n%n", a.p, a.q, aPub[1], a.phi, aPub[0], a.d);
        RSA b = new RSA(4096);
        BigInteger[] bPub = b.getPubKey();
        System.out.printf("p = %s%nq = %s%nn = %s%nphi = %s%ne = %s%nd = %s%n%n", b.p, b.q, bPub[1], b.phi, bPub[0], b.d);

        String message1 = "Hello";
        System.out.printf("msg: %s%n", message1);
        String signed1 = a.sign(message1);
        System.out.printf("Signed by A ({msg}privA): %s%n", signed1);
        String cipher1 = a.encrypt(signed1, bPub);
        System.out.printf("Sent to B ({{msg}privA}pubB): %s%n", cipher1);

        String auth1 = b.decrypt(cipher1);
        System.out.printf("Received by B ({msg}privA): %s%n", auth1);
        
        String plain1 = b.authenticate(auth1, aPub);
        System.out.printf("Authenticated by B: %s%n", plain1);

        String message2 = "";
        System.out.printf("msg: %s%n", message2);
        String cipher2 = b.encrypt(message2, aPub);
        System.out.printf("Sending to A ({msg}pubA): %s%n", cipher2);
        String signed2 = b.sign(cipher2);
        System.out.printf("Signed by B ({{msg}pubA}privB): %s%n", signed2);

        String auth2 = a.authenticate(signed2, bPub);
        System.out.printf("Authenticated by A ({msg}pubA): %s%n", auth2);
        String plain2 = a.decrypt(auth2);
        System.out.printf("Received by A: %s%n", plain2);
    }
}
