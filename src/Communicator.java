import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.File;
import java.io.FileNotFoundException;
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

    private String readFileToString(String fileName){
        // read file
        File file = new File(getClass().getResource(fileName).getPath());
        String messageText = " ";

        try{
            Scanner scanner = new Scanner(file);
            messageText = scanner.nextLine();
        }
        catch (FileNotFoundException e){
            e.printStackTrace();
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

    public String encryptAESKey(SecretKey aesKey, PublicKey receiverPublicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String aesKeyEncrypted = " ";

            byte[] aesKeyEncoded = aesKey.getEncoded();
            aesCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey);
            byte[] encryptedAESKey = aesCipher.doFinal(aesKeyEncoded);
            aesKeyEncrypted = encode(encryptedAESKey);

        return aesKeyEncrypted;
    }
}
