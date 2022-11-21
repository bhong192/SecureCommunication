import javax.crypto.Cipher;
import java.security.*;

public class Receiver extends Communicator {

    PrivateKey privateKey;
    PublicKey publicKey;

    // generate RSA key pair (public and private)

    // encrypt this person's message (txt file) using AES before sending

    // encrypt the AES key using the other person's RSA public key

    // send the encrypted message and AES key together (choose a protocol for MAC)

    // (receiver specific) successfully authenticate, decrypt and read the original message from the sender
}
