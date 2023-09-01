package Seguridad;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Main {

    public static void main(String[] args) throws Exception {
        // generar un par de llaves (publica, privada)
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();

        // extraer las llaves
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        // guardar llave en archivo
        try (FileOutputStream fos = new FileOutputStream("public.key")) {
            fos.write(publicKey.getEncoded());
        }

        // leer llave de archivo
        File publicKeyFile = new File("public.key");
        byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());

        // recrear llave
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        keyFactory.generatePublic(publicKeySpec);

        // mensaje a encriptar
        String str = "msj";

        // instanciar encriptacion (en este caso llave publica)
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // transformar el string a byte
        byte[] secretMessageBytes = str.getBytes(StandardCharsets.UTF_8);

        // encripta el mensaje
        byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);

        // encriptar (mensaje o llave) con base64
        String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessageBytes);

        // creamos un objeto de la clase cipher que nos va a permitir desencriptar el mensaje
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        // desencriptamos el mensaje
        byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
        String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);

        if (str.equals(decryptedMessage)){
            System.out.println(str);
            System.out.println(encryptedMessageBytes);
            System.out.println(decryptedMessage);
        }

        // hasheo del mensaje
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(str.getBytes(StandardCharsets.UTF_8));
        String sha256 = DatatypeConverter.printHexBinary(digest).toLowerCase();

        // imprimir resumen de mensaje SHA-256
        System.out.println(sha256);

    }

}
