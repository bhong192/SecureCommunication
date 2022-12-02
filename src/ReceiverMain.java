import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class ReceiverMain {

    public static void main(String[] args){
        Receiver receiver = new Receiver();
        // Receiver should decrypt AES key, decrypt message, authenticate message
        //TODO: read private RSA key from receiverPrivateKey.key and save it
        PrivateKey receiverPrivateKey = receiver.privateKey;
        try{
            File privateKeyFile = new File("receiverPrivateKey.key");
            byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath()); //read all the bytes in file
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            receiverPrivateKey = keyFactory.generatePrivate(privateKeySpec); // recreate the private key
        }catch (Exception e){
            e.printStackTrace();
        }
        System.out.println("ReceiverPrivateKey: " + receiverPrivateKey);

        try{
            String readEncryptedMessage = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(0);
            String readEncryptedKey = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(1);
            String readMAC = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(2);
            String readMacKey = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(3);

            // remove last character due to encoding error (\n)
            readEncryptedMessage = readEncryptedMessage.substring(0, readEncryptedMessage.length()-1);

            // decrypt message using the AES key
            // TODO: write function to decrypt the AES key using Receiver's private key and using that result to decrypt the message
//            SecretKey recoveredAesKey = Communicator.decryptRSA(readEncryptedKey, receiver.privateKey); // original
            String recoveredAesKey = Communicator.decryptRsaMessage(readEncryptedKey, receiverPrivateKey);

            String decryptedMessage = Communicator.decryptAES(readEncryptedMessage, recoveredAesKey);
//            String decryptedMessage = sender.decrypt(readEncryptedMessage, recoveredAesKey); // aesKey here should be obtained after decrypting it with private key instead

            // verify MAC by recalculating it from the message and comparing it to what was sent
            SecretKey recoveredMacKey = Communicator.decryptRSA(readMacKey, receiverPrivateKey);
            Mac verificationMAC = Mac.getInstance("HmacMD5");
            verificationMAC.init(recoveredMacKey);

            byte[] decryptedMessageBytes = decryptedMessage.getBytes();
            byte[] recalculatedMAC = verificationMAC.doFinal(decryptedMessageBytes);
            String recalculatedMACString = new String(recalculatedMAC);

            // STEP 7: Print status of verifications (intact message and valid MAC)
            System.out.println("Decrypted Message: " + decryptedMessage);
            System.out.println("Valid MAC Status: " + recalculatedMACString.equals(readMAC));
        }
        catch(Exception e){
            e.printStackTrace();
        }

//        try{
//            String readEncryptedMessage = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(0);
//            String readEncryptedKey = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(1);
//            String readMAC = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(2);
//            String readMacKey = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(3);
//
//            // remove last character due to encoding error (\n)
//            readEncryptedMessage = readEncryptedMessage.substring(0, readEncryptedMessage.length()-1);
//            //readEncryptedKey = readEncryptedKey.substring(0, readEncryptedKey.length()-1);
//
//            // decrypt message using the AES key
////            // TODO: read receiver's private key from receiverPrivateKey.priv
////            File privateKeyFile = new File("receiverPrivateKey.priv");
////            byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
////            KeyFactory privateKeyFactory = KeyFactory.getInstance("RSA");
////            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
////            PrivateKey receiverPrivateKey = privateKeyFactory.generatePrivate(privateKeySpec);
////            System.out.println("Private key size: " + receiverPrivateKey.getEncoded().length);
//            System.out.println("readEncryptedKey: " + readEncryptedKey);
//            System.out.println("receiverPrivateKey: " + receiverPrivateKey);
//            SecretKey recoveredAesKey = Communicator.decryptRSA(readEncryptedKey, receiverPrivateKey);
//            String decryptedMessage = Communicator.decrypt(readEncryptedMessage, recoveredAesKey); // aesKey here should be obtained after decrypting it with private key instead
//
//            // verify MAC by recalculating it from the message and comparing it to what was sent
//            // TODO: Decrypt MAC key and recalculate to verify message integrity
//            SecretKey recoveredMacKey = Communicator.decryptRSA(readMacKey, receiverPrivateKey);
//            Mac mac = Mac.getInstance("HmacMD5");
//            mac.init(recoveredMacKey);
//            byte[] decryptedMessageBytes = decryptedMessage.getBytes();
//            byte[] recalculatedMAC = mac.doFinal(decryptedMessageBytes);
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
