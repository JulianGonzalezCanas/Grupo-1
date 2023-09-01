import java.net.*;
import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class TCPClient {

    public static byte[] receiveKey(Socket socketCliente, PublicKey clientPub) throws IOException {

        BufferedReader entrada = new BufferedReader(new InputStreamReader(socketCliente.getInputStream()));
        String respuesta = entrada.readLine();
        byte[] publicKey = respuesta.getBytes();

        OutputStream outputStream = socketCliente.getOutputStream();
        outputStream.write(clientPub.getEncoded());

        return publicKey;
    }
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        Socket socketCliente = null;
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();

        try {
            socketCliente = new Socket("172.16.255.170", 2556);

        } catch (IOException e) {
            System.err.println("No puede establer canales de E/S para la conexion");
            System.exit(-1);
        }

        byte[] serverPub = receiveKey(socketCliente, pair.getPublic());

        Thread hiloEscucha = new Thread(new HiloRecibo(socketCliente));

        Thread hiloEnvio = new Thread((new HiloEnvio(socketCliente, serverPub, pair.getPrivate())));

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
}