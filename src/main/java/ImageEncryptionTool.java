import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ImageEncryptionTool {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 128;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter 'E' to encrypt or 'D' to decrypt:");
        String operation = scanner.nextLine().toUpperCase();

        System.out.println("Enter the file path:");
        String filePath = scanner.nextLine();

        try {
            if (operation.equals("E")) {
                encryptFile(filePath);
            } else if (operation.equals("D")) {
                decryptFile(filePath);
            } else {
                System.out.println("Invalid operation. Please enter 'E' or 'D'.");
            }
        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
        } finally {
            scanner.close();
        }
    }
    private static void encryptFile(String filePath) throws Exception {
        File inputFile = new File(filePath);
        if (!inputFile.exists()) {
            System.out.println("Error encrypting image: Can't read input file!");
            return;
        }

        SecretKey key = generateKey(KEY_SIZE);
        IvParameterSpec iv = generateIv();

        // Store the key and IV in a file
        FileOutputStream keyOutputStream = new FileOutputStream("key.bin");
        keyOutputStream.write(key.getEncoded());
        keyOutputStream.close();

        FileOutputStream ivOutputStream = new FileOutputStream("iv.bin");
        ivOutputStream.write(iv.getIV());
        ivOutputStream.close();

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream("encrypted_images/" + getFileName(inputFile) + "_encrypted.jpg");

        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }

        inputStream.close();
        outputStream.close();
    }

    private static void decryptFile(String filePath) throws Exception {
        File inputFile = new File(filePath);
        if (!inputFile.exists()) {
            System.out.println("Error decrypting image: Can't read input file!");
            return;
        }

        // Load the key and IV from the file
        FileInputStream keyInputStream = new FileInputStream("key.bin");
        byte[] keyBytes = new byte[(int) new File("key.bin").length()];
        keyInputStream.read(keyBytes);
        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        FileInputStream ivInputStream = new FileInputStream("iv.bin");
        byte[] ivBytes = new byte[(int) new File("iv.bin").length()];
        ivInputStream.read(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream("decrypted_images/" + getFileName(inputFile) + "_decrypted.jpg");

        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer))!= -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output!= null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes!= null) {
            outputStream.write(outputBytes);
        }

        inputStream.close();
        outputStream.close();
    }

    private static SecretKey generateKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    private static IvParameterSpec generateIv() {
        byte[] ivBytes = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);
        return new IvParameterSpec(ivBytes);
    }

    private static String getFileName(File file) {
        return file.getName().substring(0, file.getName().lastIndexOf('.'));
    }
}