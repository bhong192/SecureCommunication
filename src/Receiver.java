import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.security.*;
import java.util.Scanner;

public class Receiver extends Communicator {
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
