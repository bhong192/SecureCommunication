import javax.crypto.*;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        // TODO: STEP 1: Generate RSA key pairs for both receiver and sender and write to their key txt files
        Receiver receiver = new Receiver();
        receiver.createKeyPair();

        Sender sender = new Sender();
        sender.createKeyPair();

        // create AES key (symmetric so only one needed for both parties)
        SecretKey aesKey = Communicator.generateAESkey();

        // STEP 2: Encrypt each person's message using the AES key
        String receiverEncryptedMessage = receiver.encryptMessage("receiver.txt", aesKey);
        String senderEncryptedMessage = sender.encryptMessage("sender.txt", aesKey);

        // STEP 3: Encrypt the AES key using RSA private key of the sender
        String encryptedAESKEY = receiver.encryptAESKey(aesKey, receiver.publicKey);
        System.out.println("Encrypted AES Key: " + encryptedAESKEY);

        // TODO: STEP 4: Create MAC
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        SecureRandom secureRandom = new SecureRandom();
        keyGenerator.init(secureRandom);
        Key key = keyGenerator.generateKey();

        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(key);

        Communicator communicator = new Communicator();
        String message = communicator.readFileToString("sender.txt");
        byte[] messageBytes = message.getBytes();
        byte[] macResultArray = mac.doFinal(messageBytes);
        String macResult = new String(macResultArray);
        System.out.println("Mac Result: " + new String(macResultArray));
        System.out.println("Mac Result Size: " + macResult.length());



        byte[] macResult2 = mac.doFinal(messageBytes);
        System.out.println("Mac Result 2: " + new String(macResult2));

        // STEP 5: Write to file: encrypted message, encrypted AES key, MAC
        try{
            FileWriter fileWriter = new FileWriter("src/resources/transmission.txt");
            String content = senderEncryptedMessage + " \n" + encryptedAESKEY + "\n" + new String(macResult);
            fileWriter.write(content);
            fileWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // TODO: STEP 6: Have Receiver read the transmission text file to authenticate and decrypt the message
            // read content from file line by line and store into individual strings
        try{
            String readEncryptedMessage = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(0);
            String readEncryptedKey = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(1);
            String readMAC = Files.readAllLines(Paths.get("src/resources/transmission.txt")).get(2);

            // remove last character due to encoding error (\n)
            readEncryptedMessage = readEncryptedMessage.substring(0, readEncryptedMessage.length()-1);
            readEncryptedKey = readEncryptedKey.substring(0, readEncryptedKey.length()-1);

            // decrypt message using the AES key
                // TODO: write function to decrypt the AES key using Receiver's private key and using that result to decrypt the message
            String decryptedMessage = sender.decrypt(readEncryptedMessage, aesKey);
            System.out.println(decryptedMessage);

            // verify MAC by recalculating it from the message and comparing it to what was sent
            byte[] decryptedMessageBytes = decryptedMessage.getBytes();
            byte[] recalculatedMAC = mac.doFinal(decryptedMessageBytes);
            String recalculatedMACString = new String(recalculatedMAC);

            System.out.println("Recalculated Mac: " + recalculatedMACString);
            char[] string = recalculatedMACString.toCharArray();
            System.out.println("Mac verification array: " + Arrays.toString(string));

            System.out.println("Mac verification size: " + recalculatedMACString.length());
            if(recalculatedMACString.equals(macResult)){
                System.out.println("Macs match");
            }
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }
}