import javax.crypto.*;
import java.security.*;

public class Sender extends Communicator {

    PrivateKey privateKey;
    PublicKey publicKey;
    Cipher encryptionCipher;
    Cipher decryptionCipher;
    Cipher aesCipher;

    public void createKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }

}
