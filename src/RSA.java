import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class RSA {

    private static final int KEY_SIZE = 2048;

    /**
     * Encrypts a message string character by character using the public exponent and modulus.
     * Applies the formula: c = m^e (mod n) for each character's integer value m.
     * WARNING: Insecure textbook RSA implementation (no padding). For learning only.
     *
     * @param message The plaintext message string.
     * @param exp     The public exponent 'e'.
     * @param mod     The modulus 'n'.
     * @return A list of BigIntegers representing the encrypted characters.
     */
    public static List<BigInteger> encrypt(String message, BigInteger exp, BigInteger mod) {
        List<BigInteger> encryptedBlocks = new ArrayList<>();
        System.out.println("\n--- Encrypting RSA---");
        System.out.println("Message: '" + message + "'");
        // System.out.println("Using Public Key (e=" + exp + ", n=" + mod + ")");

        for (char character : message.toCharArray()) {
            BigInteger m = BigInteger.valueOf((int) character);
            if (m.compareTo(mod) >= 0) {
                throw new IllegalArgumentException("Message character '" + character + "' (" + m + ") is too large for modulus n=" + mod);
            }
            // Core RSA formula: c = m^e mod n
            BigInteger c = m.modPow(exp, mod);
            encryptedBlocks.add(c);
            // System.out.println("Char: '" + character + "' (" + m + ") -> Encrypted: " + c); // Ciphertext can be huge
        }
        System.out.println("Encryption complete (manual formula).");
        return encryptedBlocks;
    }

    /**
     * Decrypts a list of encrypted BigIntegers using the private exponent and modulus.
     * Applies the formula: m = c^d (mod n) for each encrypted number c.
     * WARNING: Insecure textbook RSA implementation (no padding). For learning only.
     *
     * @param encryptedData A list of BigIntegers representing the encrypted characters.
     * @param exp           The private exponent 'd'.
     * @param mod           The modulus 'n'.
     * @return The decrypted plaintext message string.
     */
    public static String decrypt(List<BigInteger> encryptedData, BigInteger exp, BigInteger mod) {
        StringBuilder decryptedMessage = new StringBuilder();
        System.out.println("\n--- Decrypting ---");
        // System.out.println("Using Private Key (d=" + exp + ", n=" + mod + ")"); // d and n can be huge

        for (BigInteger c : encryptedData) {
            if (c.compareTo(mod) >= 0 || c.compareTo(BigInteger.ZERO) < 0) {
                throw new IllegalArgumentException("Invalid ciphertext block: " + c + " (must be 0 <= c < n)");
            }
            // Core RSA formula: m = c^d mod n
            BigInteger m = c.modPow(exp, mod);
            try {
                char character = (char) m.intValueExact(); // Convert back to char
                decryptedMessage.append(character);
                // System.out.println("Encrypted: " + c + " -> Decrypted: '" + character + "' (" + m + ")");
            } catch (ArithmeticException ae) {
                System.err.println("Warning: Decrypted number " + m + " cannot be converted to char. Skipping.");
                // Handle cases where the decrypted number might not be a valid character code
                // This could happen with corrupted data or if non-character data was encrypted
            }
        }
        System.out.println("Decryption complete (manual formula).");
        return decryptedMessage.toString();
    }


    public static void main(String[] args) {
        System.out.println("RSA: Standard Key Generation + Manual Encryption/Decryption Math");
        System.out.println("Key size: " + KEY_SIZE + " bits");
        System.out.println("WARNING: Manual crypto part is insecure (no padding) - For Learning Only!");
        System.out.println("--------------------------------------------------------------");

        try {
            // Step 1: Create a KeyPairGenerator instance for RSA
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            // Step 2: Initialize the key size
            keyPairGen.initialize(KEY_SIZE);

            // Step 3: Generate the key pair
            System.out.println("Generating RSA key pair...");
            KeyPair keyPair = keyPairGen.generateKeyPair();
            System.out.println("Key pair generated successfully.");

            // Step 4: Retrieve the public and private keys
            PublicKey genericPublicKey = keyPair.getPublic();
            PrivateKey genericPrivateKey = keyPair.getPrivate();

            // --- Step 5: Extract e, d, n from the keys ---
            System.out.println("Extracting mathematical components (e, d, n) from keys...");

            BigInteger modulus;      // n
            BigInteger publicExp;    // e
            BigInteger privateExp;   // d

            // Cast to RSA specific interfaces to access methods
            if (genericPublicKey instanceof RSAPublicKey && genericPrivateKey instanceof RSAPrivateKey) {
                RSAPublicKey rsaPublicKey = (RSAPublicKey) genericPublicKey;
                RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) genericPrivateKey;

                modulus = rsaPublicKey.getModulus(); // Or rsaPrivateKey.getModulus()
                publicExp = rsaPublicKey.getPublicExponent();
                privateExp = rsaPrivateKey.getPrivateExponent();

                System.out.println("Successfully extracted n, e, d.");
                // Optionally print them, but they can be very large
                // System.out.println("  Modulus n ({} bits): {}", modulus.bitLength(), modulus.toString().substring(0, Math.min(60, modulus.toString().length())) + "...");
                // System.out.println("  Public Exponent e: " + publicExp);
                // System.out.println("  Private Exponent d ({} bits): {}", privateExp.bitLength(), privateExp.toString().substring(0, Math.min(60, privateExp.toString().length())) + "...");

            } else {
                System.err.println("Error: Keys generated are not standard RSA keys.");
                return;
            }
            System.out.println("--------------------------------------------------------------");

            // --- Step 6: Use extracted components with manual encryption/decryption ---
            Scanner originalMessageFile = new Scanner(new FileReader("src/message.txt"));
            String originalMessage = originalMessageFile.nextLine();

            // Encrypt using extracted e and n
            List<BigInteger> encryptedData = encrypt(originalMessage, publicExp, modulus);
            System.out.println("Encrypted Data (list of BigIntegers): " + encryptedData); // Will be large numbers

            String fileName = "src/outputEncrypted.txt";
            PrintWriter writer = new PrintWriter(new FileWriter(fileName));
            for (BigInteger number : encryptedData) {
                writer.println(number.toString()); // Convert BigInteger to String and write with a newline
            }
            System.out.println("Successfully wrote the encrypted data to " + fileName);

            // Decrypt using extracted d and n
            String decryptedMessage = decrypt(encryptedData, privateExp, modulus);
            System.out.println("\nDecrypted Message: '" + decryptedMessage + "'");

            FileWriter writerNew = new FileWriter("src/outputDecrypted.txt");
            writerNew.write(decryptedMessage);
            writerNew.close();
            System.out.println("Successfully wrote the string to output");

            // Verify
            System.out.println("\nVerification:");
            System.out.println("Original matches decrypted: " + originalMessage.equals(decryptedMessage));


        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error: RSA algorithm not available. " + e.getMessage());
            e.printStackTrace();
        } catch (ClassCastException e) {
            System.err.println("Error: Could not cast generic keys to RSA specific keys. " + e.getMessage());
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            System.err.println("Error during encryption/decryption: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) { // Catch unexpected errors
            System.err.println("An unexpected error occurred: " + e.getMessage());
            e.printStackTrace();
        }
        System.out.println("\n--- End of Demonstration ---");
    }
}