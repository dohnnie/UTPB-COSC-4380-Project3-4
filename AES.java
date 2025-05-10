import java.util.HashMap;
import java.math.BigInteger;

public class AES {

    //private String[] keySchedule = new String[11];

    private static final HashMap<Integer, Integer> RC = new HashMap<>();
    static {
        RC.put(1, 0x01);
        RC.put(2, 0x02);
        RC.put(3, 0x04);
        RC.put(4, 0x08);
        RC.put(5, 0x10);
        RC.put(6, 0x20);
        RC.put(7, 0x40);
        RC.put(8, 0x80);
        RC.put(9, 0x1B);
        RC.put(10, 0x36);
    }

    private String[] roundKey = new String[11]; // round keys for AES-128
    private int[] words = new int[44]; // 4 words for AES-128

    private String[][] iv = new String[4][4]; // Initialization vector (IV) for CBC mode

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ///  CONSTRUCTORS                                                                                                      ///
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public AES(String key) {
        // Check if the key is valid
        if (key.length() < 16) {
            throw new IllegalArgumentException("Key must be at least 16 characters long.");
        }
        // Initialize the key schedule and round keys
        for (int j = 0; j < this.roundKey.length; j++)  {
            this.roundKey[j] = ""; // Initialize round keys to empty strings
        }
        keyExpansion(key); // Generate the key schedule from the provided key.

        // String[][] blockA = hexToBlock(a);
        // String[][] blockB = hexToBlock(b);
        // String[][] xor = xorBlocks(blockA, blockB);
        // System.out.println("XOR: ");
        // printBlock(xor);

        // String test = "Two One Nine Two"; // Example plaintext (AES Debug.txt)
        // String testHex = stringToHex(test);
        // System.out.println("Hex: " + testHex);
        // testHex = assertPadding(testHex);
        // System.out.println("Hex: " + testHex);

    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ///  FUNCTIONS                                                                                                         ///
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public String encrypt(String plaintext, boolean cbcMode) {

        printKeySchedule();
        String hexPlainText = stringToHex(plaintext); // Convert plaintext to hex

        hexPlainText = assertPadding(hexPlainText); // Ensure padding is applied if needed

        int blocks = hexPlainText.length() / 32; // Calculate the number of blocks needed

        String cipherText = ""; // Initialize ciphertext


        this.iv = getRandomBlock(); // Get a random initialization vector (IV)
        String[][] lastBlock = this.iv; // Initialize the last block with the IV

        if (cbcMode) {
            Tools.debugLog("CBC Mode Enabled! Generating IV...");
            Tools.debugLog("IV: ");
            printBlock(iv); // Print the IV
        }


        for (int i = 0; i < blocks; i++) {
            String blockHex = hexPlainText.substring(i * 32, (i + 1) * 32); // Get the current block
            String[][] block = hexToBlock(blockHex); // Convert hex string to block (4x4 matrix)

            if (cbcMode) {
                block = xorBlocks(block, lastBlock); // XOR the block with the last block (or IV for the first block)
                Tools.debugLog("XORing with last block: ");
                printBlock(block); // Print the XORed block
            }
            
            cipher(block, true); // Encrypt the block
            cipherText += blockToHex(block); // Add block to total output ciphertext
            lastBlock = block; // Update the last block value with the current block
        }

        return cipherText;
    }

    public String[][] xorBlocks(String[][] block1, String[][] block2) {
        String[][] result = new String[4][4]; // Create a new block to store the result
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                result[i][j] = Integer.toHexString(Integer.parseInt(block1[i][j], 16) ^ Integer.parseInt(block2[i][j], 16)); // XOR the blocks
                result[i][j] = String.format("%2s", result[i][j]).replace(' ', '0'); // Pad with leading zeros
            }
        }
        return result;
    }

    public String[][] getRandomBlock() {
        String[][] block = new String[4][4]; // Create a new block to store the random values
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                block[i][j] = Integer.toHexString((int) (Math.random() * 256)); // Generate random hex values
                block[i][j] = String.format("%2s", block[i][j]).replace(' ', '0'); // Pad with leading zeros
            }
        }
        return block;
    }

    public static String[][] deepCopy(String[][] original) {
        String[][] copy = new String[original.length][];
        for (int i = 0; i < original.length; i++) {
            copy[i] = original[i].clone(); // or use Arrays.copyOf(original[i], original[i].length);
        }
        return copy;
    }

    public String decrypt(String ciphertext, boolean cbcMode) {
        printKeySchedule();

        int blocks = ciphertext.length() / 32; // Calculate the number of blocks needed

        String plainText = ""; // Initialize ciphertext

        String[][] lastBlock = this.iv; // Initialize the last block with the IV

        for (int i = 0; i < blocks; i++) {
            String blockHex = ciphertext.substring(i * 32, (i + 1) * 32); // Get the current block
            String[][] block = hexToBlock(blockHex); // Convert hex string to block (4x4 matrix)
            String[][] prevCipher = deepCopy(block); // Store the current block temporarily
            cipher(block, false); // Decrypt the block
            if (cbcMode) {
                Tools.debugLog("XORing with last block: ");
                String[][] temp = deepCopy(block); // Store the decrypted block temporarily

                printBlock(block);
                printBlock(temp); // Print the last block
                block = xorBlocks(block, lastBlock); // XOR the block with the IV
                lastBlock = prevCipher; // Update the last block value with the decrypted block
                printBlock(block); // Print the XORed block
            }
            plainText += blockToHex(block); // Add block to total output plaintext
        }

        Tools.debugLog("Plaintext: " + plainText); // Print the ciphertext
        
        String paddingRemoved = removePKCS7PaddingFromHex(plainText); // Remove PKCS#7 padding
        plainText = hexToString(paddingRemoved); // Convert hex string back to plaintext
        return plainText;
    }

    public String assertPadding(String hex) {
        if (hex.length() % 32 != 0) { // Check if the length of the hex string is a multiple of 32
            int paddingLength = 32 - (hex.length() % 32); // Calculate the padding length needed
            Tools.debugLog("Padding needed for input text! Length: " + hex.length()/2 + " Padding Length: " + paddingLength/2);
            int paddingBytes = paddingLength / 2; // Calculate the number of padding bytes needed
            for (int i = 0; i < paddingBytes; i++) {
                String temp = Integer.toHexString(paddingBytes); // Convert padding bytes to hex
                temp = String.format("%2s", temp).replace(' ', '0'); // Pad with leading zeros
                hex += temp; // Add padding bytes
            }
        } else {
            
            // Pad with 0x10 if the length is a multiple of 32
            String temp = Integer.toHexString(0x10); // Convert 0x10 to hex
            for (int i = 0; i < 16; i++) {
                temp = String.format("%2s", temp).replace(' ', '0'); // Pad with leading zeros
                hex += temp; // Add padding bytes
            }
        }
        return hex; // Return the padded hex string
    }

    public String cipher(String[][] block, boolean encryptMode) {
        if (encryptMode) {
            addRoundKey(block, this.roundKey[0]);

            for (int round = 1; round < 10; round++) {
                subBytes(block, encryptMode);
                shiftRows(block, encryptMode);
                mixColumns(block, encryptMode);
                addRoundKey(block, this.roundKey[round]);
            }

            subBytes(block, encryptMode);
            shiftRows(block, encryptMode);
            addRoundKey(block, this.roundKey[10]);
        } else {
            addRoundKey(block, roundKey[10]);
            shiftRows(block, encryptMode);
            subBytes(block, encryptMode);

            for (int round = 1; round < 10; round++) {
                addRoundKey(block, roundKey[10 - round]);
                mixColumns(block, encryptMode);
                shiftRows(block, encryptMode);
                subBytes(block, encryptMode);
            }

            addRoundKey(block, this.roundKey[0]);
        }
        return "";
    }

    public static String stringToHex(String str) {
        StringBuilder hexString = new StringBuilder();
        for (char c : str.toCharArray()) { // Convert each character to its hex representation
            hexString.append(String.format("%02x", (int) c)); // Convert char to hex
        }
        return hexString.toString();
    }

    public static String removePKCS7PaddingFromHex(String hex) {
        if (hex.length() < 2 || hex.length() % 2 != 0)
            throw new IllegalArgumentException("Hex string must have even length and be non-empty.");

        int paddingByte = Integer.parseInt(hex.substring(hex.length() - 2), 16);
        int totalBytes = hex.length() / 2;

        if (paddingByte < 1 || paddingByte > 16 || paddingByte > totalBytes)
            throw new IllegalArgumentException("Invalid PKCS#7 padding value: " + paddingByte);

        return hex.substring(0, hex.length() - (paddingByte * 2));
    }


    public static String hexToString(String hex) {
        StringBuilder str = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) { // Convert each pair of hex digits to a character
            String subStr = hex.substring(i, i + 2);
            str.append((char) Integer.parseInt(subStr, 16)); // Convert hex to char
        }
        return str.toString();
    }
    // private byte[][] getBlock(String text, int blockIdx) {

    // }

    /**
     * <h3>keyExpansion</h3>
     * <p>>Accepts a hex string and expands it to have a total of 11 round keys.</p>
     * @param hex A hex string representing the key.
     */
    private void keyExpansion(String key) {
        // TODO: Implement padding if a small key is used and cutoff is a large key is used.

        // First, grab the first 4 words from our key
        String hexKey = stringToHex(key);
        for (int i = 0; i < 4; i++) {
            this.words[i] = Integer.parseInt(hexKey.substring(i * 8, (i + 1) * 8), 16); // Convert hex to int
        }
        // Next, we will generate the remaining 40 words using the key schedule
        for (int i = 4; i < 44; i++) {
            
            if (i % 4 == 0) {
                int rconWord = RC.get(i/4) << 24;
                this.words[i] = this.words[i - 4] ^ bytesToIntWord(subWord(rotWord(intWordToBytes(this.words[i - 1])))) ^ rconWord; // XOR with previous word and round constant
            } else {
                this.words[i] = this.words[i - 4] ^ this.words[i - 1]; // XOR with previous word
            }
        }

        for (int i = 0; i < 44; i++) {
            roundKey[i / 4] += String.format("%08x", this.words[i]); // Convert each word to hex and append to round key
        }

    }
    
    /**
     * <h3>hexToBlock</h3>
     * <p>Accepts a hex string an arranges it in column major form (4x4 matrix).</p>
     * @param hex A hex string representing the block of data.
     * @return String[][] - The hex string arranged in column major form (4x4 matrix).
     */
    private String[][] hexToBlock(String hex) {
        String[][] block = new String[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                block[j][i] = hex.substring((i * 8) + (j * 2), (i * 8) + (j * 2) + 2); // Convert hex to int
            }
        }
        return block;
    }
 
    public static String blockToHex(String[][] block) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                hex.append(block[j][i]); // Convert block to hex
            }
        }
        return hex.toString();
    }

    public static void printBlock(String[][] block) {
        if (Tools.DEBUG) {
                for (int i = 0; i < 4; i++) {
                    for (int j = 0; j < 4; j++) {
                        System.out.print(block[i][j] + "");
                    }
                    System.out.println();
            }
            System.out.println();
        }
    }

    public static int[] intWordToBytes(int wordInt) {
        String hex = Integer.toHexString(wordInt);
        int[] bytes = new int[4];
        bytes[0] = Integer.parseInt(hex.substring(0, 2), 16); // First byte
        bytes[1] = Integer.parseInt(hex.substring(2, 4), 16); // Second byte
        bytes[2] = Integer.parseInt(hex.substring(4, 6), 16); // Third byte
        bytes[3] = Integer.parseInt(hex.substring(6, 8), 16); // Fourth byte
        return bytes;
    }

    public static int bytesToIntWord(int[] bytes) {
        return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]; // Combine bytes into an int
    }

    private int[] rotWord(int[] word) {
        int[] rot = new int[4];
        rot[0] = word[1];
        rot[1] = word[2];
        rot[2] = word[3];
        rot[3] = word[0];
        return rot;
    }

    // Apply SubWord (substitute bytes using the AES S-box)
    private int[] subWord(int[] word) {
        int[] sub = new int[4];
        for (int i = 0; i < word.length; i++) {
            sub[i] = SBox.sbox(word[i]); // Apply S-box substitution
        }
        return sub;
    }

    private void subBytes(String[][] block, boolean mode) {
        Tools.debugLog("Substituting Bytes");

        printBlock(block); // Print the original block

        int[][] blockInt = new int[4][4]; // Create a new block to store the substituted values

        for(int r = 0; r < 4; r++) {
            for(int c = 0; c < 4; c++) {
                blockInt[r][c] = mode ? SBox.sbox(Integer.parseInt(block[r][c], 16)) : SBox.invSbox(Integer.parseInt(block[r][c], 16));
                block[r][c] = String.format("%2s", Integer.toHexString(blockInt[r][c])).replace(' ', '0'); // Convert to hex and pad with leading zeros
            }
        }

        printBlock(block); // Print the block after substitution
    }

    private void shiftRows(String[][] block, boolean mode) {
        Tools.debugLog("Shifting Rows");
        printBlock(block); // Print the original block

        for (int r = 1; r < 4; r++) {
            String[] temp = new String[4];
            for (int c = 0; c < 4; c++) {
                temp[c] = mode ? block[r][(c+r)%4] : block[r][(c-r+4)%4];
            }
            block[r] = temp;
        }

        printBlock(block); // Print the block after shifts
    }

    private int mulBy2(int b) {
        int result = b << 1;
        if ((b & 0x80) != 0) {
            result ^= 0x1b;
        }
        return result & 0xFF; // Keep it in 0–255 range
    }

    private int mulBy3(int b) {
        return mulBy2(b) ^ b;
    }
    
    // b in 0–255
    private int mulBy9(int  b) { return mulBy2(mulBy2(mulBy2(b))) ^ b;          }
    private int mulBy11(int b) { return mulBy2(mulBy2(mulBy2(b))) ^ mulBy2(b) ^ b; }
    private int mulBy13(int b) { return mulBy2(mulBy2(mulBy2(b))) ^ mulBy2(mulBy2(b)) ^ b; }
    private int mulBy14(int b) { return mulBy2(mulBy2(mulBy2(b))) ^ mulBy2(mulBy2(b)) ^ mulBy2(b); }

    private void mixColumns(String[][] block, boolean mode) {
        Tools.debugLog("Mixing Columns");
        printBlock(block); // Print the original block
        if (mode) {
            // Encrypt - Mix Columns
            for (int i = 0; i < 4; i++) {
                int[] col = new int[4]; // Create a new array to store the column values

                // Convert hex to int
                for (int j = 0; j < 4; j++) {
                    col[j] = Integer.parseInt(block[j][i], 16); // Convert hex to int
                }

                int s0 = col[0], s1 = col[1], s2 = col[2], s3 = col[3];

                int[][] blockInt = new int[4][4]; // Create a new block to store the mixed values

                blockInt[0][i] = (mulBy2(s0) ^ mulBy3(s1) ^ s2 ^ s3);
                blockInt[1][i] = (s0 ^ mulBy2(s1) ^ mulBy3(s2) ^ s3);
                blockInt[2][i] = (s0 ^ s1 ^ mulBy2(s2) ^ mulBy3(s3));
                blockInt[3][i] = (mulBy3(s0) ^ s1 ^ s2 ^ mulBy2(s3));

                block[0][i] = String.format("%2s", Integer.toHexString(blockInt[0][i])).replace(' ', '0'); // Convert to hex and pad with leading zeros
                block[1][i] = String.format("%2s", Integer.toHexString(blockInt[1][i])).replace(' ', '0'); // Convert to hex and pad with leading zeros
                block[2][i] = String.format("%2s", Integer.toHexString(blockInt[2][i])).replace(' ', '0'); // Convert to hex and pad with leading zeros
                block[3][i] = String.format("%2s", Integer.toHexString(blockInt[3][i])).replace(' ', '0'); // Convert to hex and pad with leading zeros
            }

        } else {
            // Decrypt - Inverse Mix
            for (int i = 0; i < 4; i++) {
                int[] col = new int[4]; // Create a new array to store the column values

                // Convert hex to int
                for (int j = 0; j < 4; j++) {
                    col[j] = Integer.parseInt(block[j][i], 16); // Convert hex to int
                }

                int s0 = col[0], s1 = col[1], s2 = col[2], s3 = col[3];

                int[][] blockInt = new int[4][4]; // Create a new block to store the mixed values

                blockInt[0][i] = mulBy14(s0) ^ mulBy11(s1) ^ mulBy13(s2) ^ mulBy9(s3);
                blockInt[1][i] = mulBy9(s0)  ^ mulBy14(s1) ^ mulBy11(s2) ^ mulBy13(s3);
                blockInt[2][i] = mulBy13(s0) ^ mulBy9(s1)  ^ mulBy14(s2) ^ mulBy11(s3);
                blockInt[3][i] = mulBy11(s0) ^ mulBy13(s1) ^ mulBy9(s2)  ^ mulBy14(s3);

                block[0][i] = String.format("%2s", Integer.toHexString(blockInt[0][i])).replace(' ', '0'); // Convert to hex and pad with leading zeros
                block[1][i] = String.format("%2s", Integer.toHexString(blockInt[1][i])).replace(' ', '0'); // Convert to hex and pad with leading zeros
                block[2][i] = String.format("%2s", Integer.toHexString(blockInt[2][i])).replace(' ', '0'); // Convert to hex and pad with leading zeros
                block[3][i] = String.format("%2s", Integer.toHexString(blockInt[3][i])).replace(' ', '0'); // Convert to hex and pad with leading zeros
            }
        }
        // Print the block after mixing columns
        printBlock(block); // Print the block after mixing columns
    }

    private void addRoundKey(String[][] block, String roundKey) {
        Tools.debugLog("Adding Round Key");

        String[][] roundKeyBlock = hexToBlock(roundKey); // Convert the round key to a block

        printBlock(block); // Print the original block
        printBlock(roundKeyBlock); // Print the round key block

        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                block[r][c] = Integer.toHexString(Integer.parseInt(block[r][c], 16) ^ Integer.parseInt(roundKeyBlock[r][c], 16));
                block[r][c] = String.format("%2s", block[r][c]).replace(' ', '0'); // Pad with leading zeros
            }
        }
        printBlock(block); // Print the block after adding the round key
    }

    private void printKeySchedule() {
        Tools.debugLog("\nKey Schedule:");
        for (int i = 0; i < this.roundKey.length; i++) {
            Tools.debugLog(this.roundKey[i]);
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ///  MAIN                                                                                                              ///
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    public static void main(String[] args) {

        String plainText = "Two One Nine Two"; // Example plaintext (AES Debug.txt)
        String key = "Thats my Kung Fu"; // Example key (AES Debug.txt)
        

        System.out.println("Original: " + plainText);
        System.out.println("Key: " + key);
        
        AES aes = new AES(key); // Create our AES object with the provided example key (AES Debug.txt)
        String cipherText = aes.encrypt(plainText, true); // Encrypt the provided example plaintext (AES Debug.txt)
        System.out.println("Encrypted: " + cipherText); // Print the ciphertext in hex format

        String decryptedText = aes.decrypt(cipherText, true); // Decrypt the ciphertext
        System.out.println("Decrypted: " + decryptedText); // Print the decrypted text

    }
}
