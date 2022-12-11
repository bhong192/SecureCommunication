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

        // read RSA private key from file to decrypt AES key
        PrivateKey receiverPrivateKey = receiver.privateKey; // currently null
        try{
            File privateKeyFile = new File("receiverPrivateKey.key");
            byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath()); //read all the bytes in file
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            receiverPrivateKey = keyFactory.generatePrivate(privateKeySpec); // recreate and save the private key
        }catch (Exception e){
            e.printStackTrace();
        }

        // read content from transmission.txt to decrypt and authenticate the message
        try{
            String readEncryptedMessage = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(0);
            String readEncryptedKey = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(1);
            String readMAC = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(2);
            String readMacKey = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(3);

            // remove last character due to encoding error (\n)
            readEncryptedMessage = readEncryptedMessage.substring(0, readEncryptedMessage.length()-1);

            // decrypt message using the AES key
            String recoveredAesKey = Communicator.decryptRsaMessage(readEncryptedKey, receiverPrivateKey);
            String decryptedMessage = Communicator.decryptAES(readEncryptedMessage, recoveredAesKey);

            // verify MAC by recalculating it from the message and comparing it to what was sent
            SecretKey recoveredMacKey = Communicator.decryptRSA(readMacKey, receiverPrivateKey);
            Mac verificationMAC = Mac.getInstance("HmacSHA256");
            verificationMAC.init(recoveredMacKey); // reinitialize MAC object with the recovered MAC key

            byte[] decryptedMessageBytes = decryptedMessage.getBytes(); // get bytes of decrypted message
            byte[] recalculatedMAC = verificationMAC.doFinal(decryptedMessageBytes); // recalculate the MAC
            String recalculatedMACString = new String(recalculatedMAC); // save as String for comparison

            // STEP 7: Print status of verifications (intact message and valid MAC)
            System.out.println("Decrypted Message from Receiver: " + decryptedMessage + "\n");
            System.out.println("Valid MAC Status from Receiver: " + recalculatedMACString.equals(readMAC)); // check if recalculated MAC matches the one read from transmission.txt
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }
}
