import java.io.FileInputStream;
import java.security.KeyPair;

public class TestSignature {

    public static void main(String[] args) throws Exception {

        FileInputStream file = new FileInputStream("zelda2.png");
        byte[] fileBytes = file.readAllBytes();

        String message = "mon message à signer";
        String secret = "secret";

        CryptoUtils utils = new CryptoUtils();
        System.out.println("Original message: "+message+"\n");
        //HMAC
        System.out.println("=============================HMAC===============================");
        String signature = utils.hmacSign(message.getBytes(), secret);
        System.out.println(signature);
        String messageAVerifier = "mon message à signer";
        System.out.println(
                (utils.hmacVerifySignature(messageAVerifier.getBytes(),signature,secret))
                        ? messageAVerifier+" est authentique"
                        :messageAVerifier+" est un fake");
        messageAVerifier = "mon message à signer!";
        System.out.println(
                (utils.hmacVerifySignature(messageAVerifier.getBytes(),signature,secret))
                        ? messageAVerifier+" est authentique"
                        :messageAVerifier+" est un fake");

        //test RSA
        System.out.println("=============================RSA===============================");
        KeyPair keyPair = utils.generateKeyPairRSA(512);
        String hash = utils.rsaSign(message.getBytes(), keyPair.getPrivate());
        System.out.println(hash);
        messageAVerifier = "mon message à signer";
        System.out.println(
                (utils.rsaVerifySignature(messageAVerifier.getBytes(), hash, keyPair.getPublic()))
                        ? messageAVerifier+" est authentique"
                        :messageAVerifier+" est un fake");
        messageAVerifier = "mon message a signer";
        System.out.println(
                (utils.rsaVerifySignature(messageAVerifier.getBytes(), hash, keyPair.getPublic()))
                        ? messageAVerifier+" est authentique"
                        :messageAVerifier+" est un fake");
    }
}
