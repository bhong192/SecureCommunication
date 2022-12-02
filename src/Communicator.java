import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class Communicator {
    static Cipher encryptionCipher;
    static Cipher decryptionCipher;
    Cipher aesCipher;

    static SecretKeySpec aesSecretKeySpec;
    static byte[] aesKey;
    public static void setKey(final String myKey){
        MessageDigest sha = null;
        try{
            aesKey = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            aesKey = sha.digest(aesKey);
            aesKey = Arrays.copyOf(aesKey, 16);
            aesSecretKeySpec = new SecretKeySpec(aesKey, "AES");
        } catch(NoSuchAlgorithmException | UnsupportedEncodingException e){
            e.printStackTrace();
        }
    }
    public static String encrypt(final String strToEncrypt, final String secret){
        try{
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesSecretKeySpec);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } catch(Exception e){
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
    public static String decryptAES(final String strToDecrypt, final String secret){
        try{
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, aesSecretKeySpec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch(Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    public static String encryptAESkey(String aesKey, PublicKey receiverPublicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] aesKeyBytes = aesKey.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey);
        byte[] encryptedAesKeyBytes = cipher.doFinal(aesKeyBytes);

        return encode(encryptedAesKeyBytes);
    }
    public static SecretKey generateAESkey() throws NoSuchAlgorithmException {
        SecretKey aesKey;
        // generate AES keys
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(192);
        aesKey = keyGenerator.generateKey();

        return aesKey;
    }

    public String readSenderMessageToString(String fileName){
        // read file
        File file = new File(getClass().getResource(fileName).getPath());
        String messageText = " ";

        Path filePath = Path.of("src/resources/sender.txt");
        try{
            messageText = Files.readString(filePath);
        }
        catch (FileNotFoundException e){
            e.printStackTrace();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return messageText;
    }

//    public String encryptMessage(String fileName, SecretKey aesKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
//        // read message file into string
//        String message = readFileToString(fileName);
//
//        // use AES to encrypt
//        byte[] messageInBytes = message.getBytes();
//        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
//        encryptionCipher.init(Cipher.ENCRYPT_MODE, aesKey);
//        byte[] encryptedMessageInBytes = encryptionCipher.doFinal(messageInBytes);
//
//        return encode(encryptedMessageInBytes);
//    }

    public static String decrypt(String encryptedMessage, SecretKey aesKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] messageInBytes = decode(encryptedMessage);
        decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, encryptionCipher.getIV());
        decryptionCipher.init(Cipher.DECRYPT_MODE,aesKey,spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(messageInBytes);
        return new String(decryptedBytes);
//        byte[] messageInBytes = decode(encryptedMessage);
//        decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
//        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
//        encryptionCipher.init(Cipher.ENCRYPT_MODE, aesKey);
//
//        System.out.println(encryptionCipher.getIV());
//        GCMParameterSpec spec = new GCMParameterSpec(128, encryptionCipher.getIV());
//        decryptionCipher.init(Cipher.DECRYPT_MODE,aesKey,spec);
//        byte[] decryptedBytes = decryptionCipher.doFinal(messageInBytes);
//        return new String(decryptedBytes);
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

    public static String decryptRsaMessage(String encryptedMessage, PrivateKey receiverPrivateKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, receiverPrivateKey);

        byte[] encryptedMessageBytes = Base64.getDecoder().decode(encryptedMessage);

        byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
        String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);
        return decryptedMessage;
    }
}

// issue is that the IVs are not the same across the 2 main methods
// need to find a way to maintain the same IV for encrypting and decrypting