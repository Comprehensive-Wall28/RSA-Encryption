import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class RSA {

    private static final SecureRandom random = new SecureRandom();

    public static BigInteger generateRandomPrime(int bitLength) {
        BigInteger prime;
        do {
            prime = new BigInteger(bitLength, random);
        } while (!prime.isProbablePrime(100)); // 100 iterations 
        return prime;
    }

    // Generate RSA keys manually
    public static BigInteger[] generateKeys(int bitLength) {
        BigInteger p = generateRandomPrime(bitLength / 2);
        BigInteger q = generateRandomPrime(bitLength / 2);
        BigInteger n = p.multiply(q); // Modulus
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)); // Euler's totient function

        BigInteger e;
        do {
            e = new BigInteger(bitLength / 2, random);
        } while (!e.gcd(phi).equals(BigInteger.ONE) || e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(phi) >= 0);

        BigInteger d = e.modInverse(phi); // Private exponent
        return new BigInteger[]{n, e, d}; //Q, PUBLIC KEY, PRIVATE KEY
    }

    public static List<BigInteger> encrypt(String message, BigInteger exp, BigInteger mod) {
        List<BigInteger> encryptedBlocks = new ArrayList<>();
        for (char character : message.toCharArray()) {
            BigInteger m = BigInteger.valueOf(character);
            encryptedBlocks.add(m.modPow(exp, mod));
        }
        return encryptedBlocks;
    }

    public static String decrypt(List<BigInteger> encryptedData, BigInteger exp, BigInteger mod) {
        StringBuilder decryptedMessage = new StringBuilder();
        for (BigInteger c : encryptedData) {
            decryptedMessage.append((char) c.modPow(exp, mod).intValue());
        }
        return decryptedMessage.toString();
    }

    public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);
            boolean check = true;
            int KEY_SIZE = 0;

            while(check){
                System.out.println("Enter key size (e.g., 2048): ");
                KEY_SIZE = scanner.nextInt();
                if(KEY_SIZE < 256){
                    System.out.println("Please enter a number more than 256!");
                }else{
                    check = false;
                }
            }
            scanner.close();

            System.out.println("Generating RSA keys...");
            BigInteger[] keys = generateKeys(KEY_SIZE);
            BigInteger n = keys[0]; // Modulus
            BigInteger e = keys[1]; // Public exponent
            BigInteger d = keys[2]; // Private exponent
            System.out.println("Keys generated successfully.");

            // Print the public and private keys
            System.out.println("Public Key: (n = " + n + ", e = " + e + ")");
            System.out.println("Private Key: (n = " + n + ", d = " + d + ")");

            Scanner originalMessageFile = new Scanner(new FileReader("src/message.txt"));
            String originalMessage = originalMessageFile.nextLine();
            originalMessageFile.close();

            // Encrypt the message
            List<BigInteger> encryptedData = encrypt(originalMessage, e, n);

            // --- Convert encrypted BigIntegers to a raw byte string ---
            ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
            for (BigInteger num : encryptedData) {
                byteStream.write(num.toByteArray());
            }
            String encryptedRawString = new String(byteStream.toByteArray()); 

            // Write encrypted data to a file
            try (FileWriter writer = new FileWriter("src/outputEncrypted.txt")) {
                writer.write("Encrypted Cipher as plaintext: \"" + encryptedRawString + "\"\n\n"); 
                writer.write("Encrypted Cipher as Big Integers:\n"); 
                for (BigInteger number : encryptedData) {
                    writer.write(number.toString() + "\n");
                }
            }

            // Decrypt the message
            String decryptedMessage = decrypt(encryptedData, d, n);
            System.out.println("Decrypted Message: " + decryptedMessage);

            // Write decrypted message to a file
            try (FileWriter writer = new FileWriter("src/outputDecrypted.txt")) {
                writer.write("Decrypted Message in Plaintext: \"" + decryptedMessage + "\"\n");
                writer.write("Decrypted Message as Big Integer:\n"); // Write the numbers
                for (BigInteger number : encryptedData) {
                    writer.write(number.toString() + "\n");
                }
            }

            // Verify
            System.out.println("Original matches decrypted: " + originalMessage.equals(decryptedMessage));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}