import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        Receiver receiver = new Receiver();
        receiver.createKey(receiver.privateKey, receiver.publicKey);

        Sender sender = new Sender();
        sender.createKey(sender.privateKey, sender.publicKey);
    }
}