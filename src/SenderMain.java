import javax.crypto.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class SenderMain {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        //STEP 1: Generate RSA key pairs (2048 bit) for both receiver and sender and write to their key files
        Receiver receiver = new Receiver();
        receiver.createKeyPair();

        Sender sender = new Sender();
        sender.createKeyPair();

        // write Receiver keys to file
        try(FileOutputStream fos =  new FileOutputStream(("receiverPublicKey.pub"))){
            fos.write(receiver.publicKey.getEncoded());
            fos.flush();
        } catch (Exception e){
            e.printStackTrace();
        }
        try(FileOutputStream fos =  new FileOutputStream(("receiverPrivateKey.pub"))){
            fos.write(receiver.privateKey.getEncoded());
            fos.flush();
        } catch (Exception e){
            e.printStackTrace();
        }

        // write Receiver's private key to a .key file and see if you can access it in the Receiver Main
        try(FileOutputStream fos = new FileOutputStream("receiverPrivateKey.key")){
            fos.write(receiver.privateKey.getEncoded()); //write the byte array of the private key to file

            File privateKeyFile = new File("receiverPrivateKey.key");
            byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath()); //read all the bytes in file
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey receiverPrivateKey = keyFactory.generatePrivate(privateKeySpec); // recreate the private key

            System.out.println("Check for private key equality: " + receiverPrivateKey.equals(receiver.privateKey));
        } catch(Exception e){
            e.printStackTrace();
        }

        // STEP 2: Create AES secret key and encrypt Sender's message
        final String aesKey = "ABCDEFGHIJKLMNOP";
        System.out.println("Number of Bytes in AES Key: " + aesKey.getBytes().length);
        String senderMessage = sender.readSenderMessageToString("sender.txt");
        System.out.println("Sender Message read from receiver.txt: " + senderMessage);
//        String senderMessage = sender.readFileToString("sender.txt");
        String senderEncryptedMessage = Communicator.encrypt(senderMessage, aesKey);

//        // TODO: create AES key (symmetric so only one needed for both parties)
//        SecretKey aesKey = Communicator.generateAESkey();
//
//        // STEP 2: Encrypt each person's message using the AES key
//        String receiverEncryptedMessage = receiver.encryptMessage("receiver.txt", aesKey);
//        String senderEncryptedMessage = sender.encryptMessage("sender.txt", aesKey);

        // STEP 3: Encrypt the AES key using RSA private key of the sender
        String encryptedAESKEY = " ";
        PublicKey receiverPublicKey = null;
        try{
            // take the Receiver's public key and use it to encrypt the AES key
            File publicKeyFile = new File("receiverPublicKey.pub");
            byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            receiverPublicKey = keyFactory.generatePublic(publicKeySpec); // save encrypted AES key
        } catch(Exception e) {
            e.printStackTrace();
        }
        encryptedAESKEY = sender.encryptAESkey(aesKey, receiverPublicKey);
        System.out.println("Encrypted AES KEY: " + encryptedAESKEY);
//        encryptedAESKEY = receiver.encryptKey(aesKey, receiverPublicKey); // encrypt the AES key using the Receiver's public key

        // STEP 4: Calculate MAC
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256"); // use DES to create symmetric key
        //SecureRandom secureRandom = new SecureRandom();
        keyGenerator.init(256);
        SecretKey key = keyGenerator.generateKey();

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);

        Communicator communicator = new Communicator();
        String message = communicator.readSenderMessageToString("sender.txt");
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

//        // TODO: STEP 6: Have Receiver read the transmission text file to authenticate and decrypt the message
//        // read content from file line by line and store into individual strings
//        try{
//            String readEncryptedMessage = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(0);
//            String readEncryptedKey = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(1);
//            String readMAC = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(2);
//            String readMacKey = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(3);
//
//            // remove last character due to encoding error (\n)
//            readEncryptedMessage = readEncryptedMessage.substring(0, readEncryptedMessage.length()-1);
//
//            // decrypt message using the AES key
//            // TODO: write function to decrypt the AES key using Receiver's private key and using that result to decrypt the message
////            SecretKey recoveredAesKey = Communicator.decryptRSA(readEncryptedKey, receiver.privateKey); // original
//            String recoveredAesKey = Communicator.decryptRsaMessage(readEncryptedKey, receiver.privateKey);
//
//            String decryptedMessage = Communicator.decryptAES(readEncryptedMessage, recoveredAesKey);
////            String decryptedMessage = sender.decrypt(readEncryptedMessage, recoveredAesKey); // aesKey here should be obtained after decrypting it with private key instead
//
//            // verify MAC by recalculating it from the message and comparing it to what was sent
//            SecretKey recoveredMacKey = Communicator.decryptRSA(readMacKey, receiver.privateKey);
//            Mac verificationMAC = Mac.getInstance("HmacMD5");
//            verificationMAC.init(recoveredMacKey);
//
//            byte[] decryptedMessageBytes = decryptedMessage.getBytes();
//            byte[] recalculatedMAC = verificationMAC.doFinal(decryptedMessageBytes);
//            String recalculatedMACString = new String(recalculatedMAC);
//
//            // STEP 7: Print status of verifications (intact message and valid MAC)
//            System.out.println("Decrypted Message: " + decryptedMessage);
//            System.out.println("Valid MAC Status: " + recalculatedMACString.equals(readMAC));
//        }
//        catch(Exception e){
//            e.printStackTrace();
//        }
    }
}