import javax.crypto.*;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        // STEP 1: Generate RSA key pairs for both receiver and sender
        Receiver receiver = new Receiver();
        receiver.createKeyPair();

        Sender sender = new Sender();
        sender.createKeyPair();

        // create AES key (symmetric so only one needed for both parties)
        SecretKey aesKey = Communicator.generateAESkey();

        // STEP 2: Encrypt each person's message using the AES key
        String receiverEncryptedMessage = receiver.encryptMessage("receiver.txt", aesKey);
        String senderEncryptedMessage = sender.encryptMessage("sender.txt", aesKey);

        // STEP 3: Create MAC

        // STEP 4: Write public AES and RSA keys to transmitted_data file
        try{
            FileWriter fileWriter = new FileWriter("transmission.txt");
            String content = receiver.publicKey.toString() + "\n" + sender.publicKey.toString() + "\n" + senderEncryptedMessage;
            fileWriter.write(content);
            fileWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // STEP 5: Encrypt the AES key using RSA private key of the sender
        String encryptedAESKEY = sender.encryptAESKey(aesKey, receiver.publicKey);
        System.out.println(encryptedAESKEY);

        // STEP 6: Concatenate the encrypted message and AES key then send to receiver


    }
}