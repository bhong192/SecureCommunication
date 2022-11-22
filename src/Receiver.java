import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.security.*;
import java.util.Scanner;

public class Receiver extends Communicator {
    PrivateKey privateKey;
    PublicKey publicKey;
    SecretKey aesKey;

    public void createKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }

    // encrypt this person's message (txt file) using AES before sending

    // encrypt the AES key using the other person's RSA public key

    // send the encrypted message and AES key together (choose a protocol for MAC)

    // (receiver specific) successfully authenticate, decrypt and read the original message from the sender
}
