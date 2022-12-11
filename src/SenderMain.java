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

        // write Sender and Receiver keys to file
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
        try(FileOutputStream fos =  new FileOutputStream(("senderPublicKey.pub"))){
            fos.write(sender.publicKey.getEncoded());
            fos.flush();
        } catch (Exception e){
            e.printStackTrace();
        }
        try(FileOutputStream fos =  new FileOutputStream(("senderPrivateKey.pub"))){
            fos.write(sender.privateKey.getEncoded());
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
            PrivateKey recoveredReceiverPrivateKey = keyFactory.generatePrivate(privateKeySpec); // recreate the private key

            System.out.println("Check for private key equality: " + recoveredReceiverPrivateKey.equals(receiver.privateKey));
        } catch(Exception e){
            e.printStackTrace();
        }

        // STEP 2: Create AES secret key and encrypt Sender's message
        final String aesKey = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"; // 32 bytes = 256 bits for key size
        System.out.println("Number of Bytes in AES Key: " + aesKey.getBytes().length + "\n");
        String senderMessage = sender.readSenderMessageToString("sender.txt");
        System.out.println("Sender Message read from sender.txt: " + senderMessage + "\n");
        String senderEncryptedMessage = Communicator.encrypt(senderMessage, aesKey);

        String receiverMessage = receiver.readSenderMessageToString("receiver.txt");
        String receiverEncryptedMessage = Communicator.encrypt(receiverMessage, aesKey); // encrypt the receiver's message

        // STEP 3: Encrypt the AES key using RSA public key of the sender
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
        encryptedAESKEY = sender.encryptAESkey(aesKey, receiverPublicKey); // encrypt the AES key using the Receiver's public key

        // STEP 4: Calculate MAC
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256"); // use DES to create symmetric key
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
            System.out.println("Successfully transmitted data!");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}