import java.security.PrivateKey;
import java.security.PublicKey;

public class Sender extends Communicator {

    PrivateKey privateKey;
    PublicKey publicKey;
    // generate RSA key pair (public and private)

    // encrypt this person's message (txt file) using AES before sending

    // encrypt the AES key using the other person's RSA public key

    // send the encrypted message and AES key together (choose a protocol for MAC)
}
