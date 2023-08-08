import java.security.KeyPair;

public class TestCrypto {
    public static void main(String[] args) throws Exception {
        String data = "mon message";
        System.out.println(data);

        CryptoUtils utils = new CryptoUtils();

        String[] pairKeyString = utils.generateKeyPairRSABase64(512);

//        String privateKey = "MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAkyVxkdEUw7mS9cESAY3kR6KN/XZBhFfGlq+G8F79I3ZpX+cl1DZdPm28RtIGcrxw2mnu4gjuUTRDZWsNlaD3IQIDAQABAkBAgzEYqh89dJYO8vfvAIOuOIGiN3+gA0/I7untZuf67JpZjEEESKkDUZ1HLZG7E9F7+vzmAGAyscZUnLSSvSTFAiEA4PG0nH3If6jIWdnrSnOZe7v/+vxHG6LiLoIa9PZTNssCIQCndhhIoZWrzD0TBA3m33L1+dXwN8kXaLpVMbDBRLjgQwIgdIDbMV34NR4evmKeeY4LxUkmmECHN6oSCVJ7UboueScCIDwtjRZ0srN1BrGRsGk5/Tb1m/LiKSp3YRaCb9FUH9e/AiBGzx7HgQZgREfTVblyDtUx0KsF9K6Q8lRXVmssjKlN+w==";
//        String publicKey = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJMlcZHRFMO5kvXBEgGN5Eeijf12QYRXxpavhvBe/SN2aV/nJdQ2XT5tvEbSBnK8cNpp7uII7lE0Q2VrDZWg9yECAwEAAQ==";

        String privateKey = pairKeyString[0];
        String publicKey = pairKeyString[1];

        String encryptData = utils.encryptRSA(data, publicKey);
        System.out.println(encryptData);
//
        System.out.println(utils.decryptRSA(encryptData, privateKey));
    }
}
