import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

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

    public static KeyPair generarLlaves() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator= KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair pair = keyPairGenerator.generateKeyPair();

        return pair;
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Socket socketCliente = null;

        try {
            socketCliente = new Socket("192.168.0.152", 2006);

        } catch (IOException e) {
            System.err.println("No puede establer canales de E/S para la conexion");
            System.exit(-1);
        }

        serverPublicKey = recibirLlave(socketCliente);
        enviarLlave(socketCliente, publicKey);

        Thread hiloEscucha = new Thread(new HiloRecibo(socketCliente));

        Thread hiloEnvio = new Thread(new HiloEnvio(socketCliente, serverPublicKey, privateKey));

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
}