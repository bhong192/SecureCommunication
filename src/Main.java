import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        // TODO: STEP 1: Generate RSA key pairs (2048 bit) for both receiver and sender and write to their key txt files
        Receiver receiver = new Receiver();
        receiver.createKeyPair();

        Sender sender = new Sender();
        sender.createKeyPair();

        // write Receiver key to .key file
        try(FileOutputStream fos =  new FileOutputStream(("public.pub"))){
            fos.write(receiver.publicKey.getEncoded());
        } catch (Exception e){
            e.printStackTrace();
        }

        // create AES key (symmetric so only one needed for both parties)
        SecretKey aesKey = Communicator.generateAESkey();

        // STEP 2: Encrypt each person's message using the AES key
        String receiverEncryptedMessage = receiver.encryptMessage("receiver.txt", aesKey);
        String senderEncryptedMessage = sender.encryptMessage("sender.txt", aesKey);

        // STEP 3: Encrypt the AES key using RSA private key of the sender
        String encryptedAESKEY = " ";
        PublicKey receiverPublicKey = null;
        try{
            // take the Receiver's public key and use it to encrypt the AES key
            File publicKeyFile = new File("public.pub");
            byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            receiverPublicKey = keyFactory.generatePublic(publicKeySpec); // save encrypted AES key
        } catch(Exception e) {
            e.printStackTrace();
        }
        encryptedAESKEY = receiver.encryptKey(aesKey, receiverPublicKey); // encrypt the AES key using the Receiver's public key

        // STEP 4: Calculate MAC
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES"); // use DES to create symmetric key
        SecureRandom secureRandom = new SecureRandom();
        keyGenerator.init(secureRandom);
        SecretKey key = keyGenerator.generateKey();

        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(key);

        Communicator communicator = new Communicator();
        String message = communicator.readFileToString("sender.txt");
        byte[] messageBytes = message.getBytes();
        byte[] macResultArray = mac.doFinal(messageBytes);
        String macResult = new String(macResultArray);

        // encrypt MAC key to send
        String encryptedMACKey = receiver.encryptKey(key, receiverPublicKey);

        // STEP 5: Write to file: encrypted message, encrypted AES key, MAC
        try{
            FileWriter fileWriter = new FileWriter("src/resources/transmission.txt");
            String content = senderEncryptedMessage + " \n" + encryptedAESKEY +"\n" + macResult + "\n" + encryptedMACKey;
            fileWriter.write(content);
            fileWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // TODO: STEP 6: Have Receiver read the transmission text file to authenticate and decrypt the message
            // read content from file line by line and store into individual strings
        try{
            String readEncryptedMessage = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(0);
            String readEncryptedKey = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(1);
            String readMAC = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(2);

            // remove last character due to encoding error (\n)
            readEncryptedMessage = readEncryptedMessage.substring(0, readEncryptedMessage.length()-1);

            // decrypt message using the AES key
                // TODO: write function to decrypt the AES key using Receiver's private key and using that result to decrypt the message
            SecretKey recoveredAesKey = Communicator.decryptRSA(readEncryptedKey, receiver.privateKey);

            String decryptedMessage = sender.decrypt(readEncryptedMessage, recoveredAesKey); // aesKey here should be obtained after decrypting it with private key instead

            // verify MAC by recalculating it from the message and comparing it to what was sent
            byte[] decryptedMessageBytes = decryptedMessage.getBytes();
            byte[] recalculatedMAC = mac.doFinal(decryptedMessageBytes);
            String recalculatedMACString = new String(recalculatedMAC);

            // STEP 7: Print status of verifications (intact message and valid MAC)
            System.out.println("Decrypted Message: " + decryptedMessage);
            System.out.println("Valid MAC Status: " + recalculatedMACString.equals(readMAC));
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }
}