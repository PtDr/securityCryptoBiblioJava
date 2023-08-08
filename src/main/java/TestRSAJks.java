import java.security.PrivateKey;
import java.security.PublicKey;

public class TestRSAJks {

    public static void main(String[] args) throws Exception {
        CryptoUtils cryptoUtils = new CryptoUtils();

        PublicKey publicKey = cryptoUtils.publicKeyFromCertification("myCertification.cert");
        PrivateKey privateKey = cryptoUtils.privateKeyFromJKS("myCrypt.jks", "saltgame", "myAlias");

        System.out.println(cryptoUtils.toBase64String(publicKey.getEncoded()));
        System.out.println(cryptoUtils.toBase64String(privateKey.getEncoded()));

        String message = "simple message non crypter";
        String messageCrypter = cryptoUtils.encryptRSA(message, publicKey);
        String messageDecrypter = cryptoUtils.decryptRSA(messageCrypter, privateKey);

        System.out.println(message);
        System.out.println(messageCrypter);
        System.out.println(messageDecrypter);
    }
}
