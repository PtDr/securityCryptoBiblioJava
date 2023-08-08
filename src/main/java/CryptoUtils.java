import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoUtils {

    public String toBase64String(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }

    public byte[] fromBase64String(String dataBase64){
        return Base64.getDecoder().decode(dataBase64.getBytes());
    }

    public String toBase64URLString(byte[] data){
        return Base64.getUrlEncoder().encodeToString(data);
    }

    public byte[] fromBase64URLString(String dataBase64){
        return Base64.getUrlDecoder().decode(dataBase64.getBytes());
    }

    public SecretKey generateRandomSecretKeyAES(Integer bitNumber) throws Exception{
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(bitNumber); //128bits ou 192bits ou 256bits

        return keyGenerator.generateKey();
    }

    public String encryptAES(String data, String secret) throws Exception{

        Cipher cipher = Cipher.getInstance("AES");
        SecretKey secretKey = new SecretKeySpec(secret.getBytes(), 0, secret.length(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE,secretKey);
        byte[] encryptData = cipher.doFinal(data.getBytes());

        return toBase64String(encryptData);
    }

    public String decryptAES(String encryptData, String secret) throws Exception{

        Cipher cipher = Cipher.getInstance("AES");
        SecretKey secretKey = new SecretKeySpec(secret.getBytes(), 0, secret.length(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE,secretKey);

        byte[] cryptedData = fromBase64String(encryptData);
        cipher.init(Cipher.DECRYPT_MODE,secretKey);
        byte[] decryptData = cipher.doFinal(cryptedData);

        return new String(decryptData);
    }

    public KeyPair generateKeyPairRSA(Integer keySize) throws NoSuchAlgorithmException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    public String[] generateKeyPairRSABase64(Integer keySize) throws NoSuchAlgorithmException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        String[] keyPairString = {toBase64String(keyPair.getPrivate().getEncoded()),toBase64String(keyPair.getPublic().getEncoded())};

        return keyPairString;
    }

    public PublicKey getPublicKeyFromKeyBase64(String publicKeyBase64) throws Exception{

        byte[] publicKeyByte = fromBase64String(publicKeyBase64);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyByte));
    }

    public PrivateKey getPrivateKeyFromKeyBase64(String privateKeyBase64) throws Exception{

        byte[] privateKeyByte = fromBase64String(privateKeyBase64);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyByte));
    }

    public String encryptRSA(String data, PublicKey publicKey) throws Exception{

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());

        return toBase64String(encryptedBytes);
    }

    public String decryptRSA(String encryptData, PrivateKey privateKey) throws Exception{

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] decryptedBytes = cipher.doFinal(fromBase64String(encryptData));

        return new String(decryptedBytes);
    }

    public String encryptRSA(String data, String publicKeyBase64) throws Exception{

        PublicKey publicKey = getPublicKeyFromKeyBase64(publicKeyBase64);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());

        return toBase64String(encryptedBytes);
    }

    public String decryptRSA(String encryptData, String privateKeyBase64) throws Exception{

        PrivateKey privateKey = getPrivateKeyFromKeyBase64(privateKeyBase64);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] decryptedBytes = cipher.doFinal(fromBase64String(encryptData));

        return new String(decryptedBytes);
    }

    public PublicKey publicKeyFromCertification(String fileName) throws Exception{
        FileInputStream fileInputStream = new FileInputStream(fileName);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(fileInputStream);

        return certificate.getPublicKey();
    }

    public PrivateKey privateKeyFromJKS(String fileName, String jksPassword, String alias) throws Exception{
        FileInputStream fileInputStream = new FileInputStream(fileName);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(fileInputStream, jksPassword.toCharArray());
        Key key = keyStore.getKey(alias, jksPassword.toCharArray());

        return (PrivateKey) key;
    }

    public PublicKey publicKeyFromCertification(File file) throws Exception{
        FileInputStream fileInputStream = new FileInputStream(file);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(fileInputStream);

        return certificate.getPublicKey();
    }

    public PrivateKey privateKeyFromJKS(File file, String jksPassword, String alias) throws Exception{
        FileInputStream fileInputStream = new FileInputStream(file);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(fileInputStream, jksPassword.toCharArray());
        Key key = keyStore.getKey(alias, jksPassword.toCharArray());

        return (PrivateKey) key;
    }

    public String hmacSign(byte[] data, String privateSecret) throws Exception{
        SecretKeySpec secretKeySpec = new SecretKeySpec(privateSecret.getBytes(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKeySpec);
        byte[] signature = mac.doFinal(data);

        return toBase64String(signature);
    }

    public Boolean hmacVerifySignature(byte[] data, String hashSigned, String privateSecret) throws Exception{
        SecretKeySpec secretKeySpec = new SecretKeySpec(privateSecret.getBytes(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKeySpec);
        byte[] signatureToVerify = mac.doFinal(data);

        return hashSigned.equals(toBase64String(signatureToVerify));
    }

    public String hashDataWithSHA256(byte[] data) throws Exception{
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(data);
        byte[] hash = md.digest();

        return toBase64String(hash);
    }

    public String hashDataWithSHA(byte[] data, Integer hashBytesNumber) throws Exception{
        MessageDigest md = MessageDigest.getInstance("SHA-"+hashBytesNumber);
        md.update(data);
        byte[] hash = md.digest();

        return toBase64String(hash);
    }

    public String rsaSign(byte[] data, PrivateKey privateKey) throws Exception{
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey, new SecureRandom());
        signature.update(data);
        byte[] sign = signature.sign();

        return toBase64String(sign);
    }

    public Boolean rsaVerifySignature(byte[] data, String hashSigned, PublicKey publicKey) throws Exception{
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        byte[] decodeSignature = fromBase64String(hashSigned);

        return signature.verify(decodeSignature);
    }
}
