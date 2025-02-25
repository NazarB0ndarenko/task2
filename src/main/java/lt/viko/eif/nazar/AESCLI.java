package lt.viko.eif.nazar;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Scanner;

public class AESCLI {
    private static final int KEY_SIZE = 16;
    private static final IvParameterSpec IV = new IvParameterSpec(new byte[16]);

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter text manually or type 'FILE' to read from file: ");
        String textInput = scanner.nextLine();
        String text = textInput.equalsIgnoreCase("FILE") ? readFromFile("encrypted.txt") : textInput;

        System.out.print("Enter secret key (16 chars): ");
        String key = scanner.nextLine();

        if (key.length() != KEY_SIZE) {
            System.out.println("Error: Key must be 16 characters long.");
            return;
        }

        System.out.print("Choose mode (ECB/CBC/CFB): ");
        String mode = scanner.nextLine().toUpperCase();

        System.out.print("Encrypt or Decrypt (E/D): ");
        String action = scanner.nextLine().toUpperCase();

        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");

        try {
            if ("E".equals(action)) {
                String encryptedText = encrypt(text, secretKey, mode);
                System.out.println("Encrypted: " + encryptedText);
                saveToFile("encrypted.txt", encryptedText);
            } else if ("D".equals(action)) {
                String decryptedText = decrypt(readFromFile("encrypted.txt"), secretKey, mode);
                System.out.println("Decrypted: " + decryptedText);
            } else {
                System.out.println("Invalid action.");
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    private static String encrypt(String plainText, SecretKeySpec secretKey, String mode) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, mode.equals("ECB") ? null : IV);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String cipherText, SecretKeySpec secretKey, String mode) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, mode.equals("ECB") ? null : IV);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private static void saveToFile(String filename, String content) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
            writer.write(content);
        }
    }

    private static String readFromFile(String filename) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            return content.toString().trim();
        } catch (IOException e) {
            System.out.println("Error reading file: " + e.getMessage());
            return "";
        }
    }
}
