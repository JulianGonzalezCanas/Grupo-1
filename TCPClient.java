import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class TCPClient {
    private static KeyPair keyPair;

    static {
        try {
            keyPair = generarLlaves();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static PublicKey publicKey = keyPair.getPublic();
    private static PrivateKey privateKey = keyPair.getPrivate();
    private static PublicKey serverPublicKey;
    private static SecretKey keySym;

    public static KeyPair generarLlaves() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator= KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair pair = keyPairGenerator.generateKeyPair();

        return pair;
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, ClassNotFoundException {
        Socket socketCliente = null;

        try {
            socketCliente = new Socket("192.168.0.152", 2921);

        } catch (IOException e) {
            System.err.println("No puede establer canales de E/S para la conexion");
            System.exit(-1);
        }

        serverPublicKey = recibirLlave(socketCliente);
        enviarLlave(socketCliente, publicKey);
        recibirLlaveSim(socketCliente);


        Thread hiloEscucha = new Thread(new HiloRecibo(socketCliente, serverPublicKey, privateKey, keySym));

        Thread hiloEnvio = new Thread(new HiloEnvio(socketCliente, serverPublicKey, privateKey, keySym));

        hiloEscucha.start();
        hiloEnvio.start();

        try {
            hiloEscucha.join();
            hiloEnvio.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        socketCliente.close();
    }

    private static PublicKey recibirLlave(Socket cliente) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        InputStream inputStream = cliente.getInputStream();
        byte[] publicKeyBytes = new byte[2048];
        inputStream.read(publicKeyBytes);

        // Convierte los bytes en una clave pública
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    private static void enviarLlave(Socket socket, PublicKey publicKey) throws IOException {
        byte[] publicKeyBytes = publicKey.getEncoded();
        OutputStream outputStream = socket.getOutputStream();
        outputStream.write(publicKeyBytes);
    }

    private static void recibirLlaveSim(Socket cliente) throws IOException, ClassNotFoundException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        ObjectInputStream inputStream = new ObjectInputStream(cliente.getInputStream());

        Object object = inputStream.readObject();
        Mensaje llaves = (Mensaje) object;
        verificarLlave(llaves);
    }

    private static void verificarLlave(Mensaje llaves) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        Cipher decryptCipher2 = Cipher.getInstance("RSA");
        decryptCipher2.init(Cipher.DECRYPT_MODE, serverPublicKey);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] llaveDesencriptada = decryptCipher.doFinal(llaves.getMensajeEncriptado());

        byte[] llaveHasheada = decryptCipher2.doFinal(llaves.getMensajeHasheado());

        byte[] llaveDesencriptadaHasheada = digest.digest(llaveDesencriptada);

        if (Arrays.equals(llaveHasheada, llaveDesencriptadaHasheada)){
            SecretKey secretKey = new SecretKeySpec(llaveDesencriptada, "AES");
            keySym = secretKey;
            System.out.println("La llave simetrica ha sido verificada y guardada");
        }
    }
}