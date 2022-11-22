import javax.crypto.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;


public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        // STEP 1: Generate RSA key pairs for both receiver and sender
        Receiver receiver = new Receiver();
        //receiver.createKeyPair(receiver.privateKey, receiver.publicKey);
        receiver.createKeyPair();

        Sender sender = new Sender();
        //sender.createKeyPair(sender.privateKey, sender.publicKey);

        // create AES key (symmetric so only one needed for both parties)
        SecretKey aesKey = Communicator.generateAESkey();
        //System.out.println(aesKey);

        // STEP 2: Encrypt each person's message using the AES key
        String receiverEncryptedMessage = receiver.encryptMessage("receiver.txt", aesKey);
        String senderEncryptedMessage = sender.encryptMessage("sender.txt", aesKey);

        // STEP 3: Encrypt the AES key using RSA private key of the sender
        String encryptedAESKEY = sender.encryptAESKey(aesKey, receiver.publicKey);
        System.out.println(encryptedAESKEY);

        // STEP 4: Concatenate the encrypted message and AES key then send to receiver




    }
}