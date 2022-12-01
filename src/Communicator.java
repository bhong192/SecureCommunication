import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class Communicator {
    Cipher encryptionCipher;
    Cipher decryptionCipher;
    Cipher aesCipher;
//    public void createKeyPair(PrivateKey privateKey, PublicKey publicKey) throws NoSuchAlgorithmException {
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        keyPairGenerator.initialize(2048);
//
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
//        privateKey = keyPair.getPrivate();
//        publicKey = keyPair.getPublic();
//    }

    public String readFileToString(String fileName){
        // read file
        File file = new File(getClass().getResource(fileName).getPath());
        String messageText = " ";

        Path filePath = Path.of("src/resources/sender.txt");
        try{
//            Scanner scanner = new Scanner(file);
//            messageText = scanner.nextLine();
            messageText = Files.readString(filePath);
        }
        catch (FileNotFoundException e){
            e.printStackTrace();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return messageText;
    }

    public static SecretKey generateAESkey() throws NoSuchAlgorithmException {
        SecretKey aesKey;
        // generate AES keys
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(192);
            aesKey = keyGenerator.generateKey();

        return aesKey;
    }

    public String encryptMessage(String fileName, SecretKey aesKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // read message file into string
        String message = readFileToString(fileName);

        // use AES to encrypt
        byte[] messageInBytes = message.getBytes();
        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedMessageInBytes = encryptionCipher.doFinal(messageInBytes);

        return encode(encryptedMessageInBytes);
    }

    public String decrypt(String encryptedMessage, SecretKey aesKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] messageInBytes = decode(encryptedMessage);
        decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, encryptionCipher.getIV());
        decryptionCipher.init(Cipher.DECRYPT_MODE,aesKey,spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(messageInBytes);
        return new String(decryptedBytes);
    }

    public static String encode(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }
    public static byte[] decode(String data){
        return Base64.getDecoder().decode(data);
    }

    public String encryptKey(SecretKey aesKey, PublicKey receiverPublicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String aesKeyEncrypted = " ";

            byte[] aesKeyEncoded = aesKey.getEncoded(); // getEncoded just turns the key into byte[]
            aesCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey); // encrypted with Receiver's RSA public key
            byte[] encryptedAESKey = aesCipher.doFinal(aesKeyEncoded); // actual encryption
            aesKeyEncrypted = encode(encryptedAESKey); // save to String for file writing purposes

        return aesKeyEncrypted;
    }

    public static SecretKey decryptRSA(String encryptedKey, PrivateKey receiverPrivateKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        byte[] encryptedKeyBytes = decode(encryptedKey);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, receiverPrivateKey);
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedKeyBytes);
        String str = new String(decryptedKeyBytes);

        // baeldung stuff
        SecretKey originalKey = new SecretKeySpec(decryptedKeyBytes, 0, decryptedKeyBytes.length, "AES");
        return originalKey;

    }
}
