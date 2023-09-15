import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class TCPServer {

    private HashMap<Socket, PublicKey> clients;

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

    public TCPServer(){
        clients = new HashMap<>();
    }

    public void start(int port) {
        try {
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Servidor iniciado en el puerto " + port);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                PublicKey publicaCliente = null;

                enviarLlave(clientSocket, publicKey);
                publicaCliente = recibirLlave(clientSocket);

                clients.put(clientSocket, publicaCliente);
                System.out.println("Nuevo cliente conectado: " + clientSocket.getInetAddress().getHostAddress());
                System.out.println(publicaCliente);

                ClientHandler clientHandler = new ClientHandler(clientSocket);
                Thread clientThread = new Thread(clientHandler);
                clientThread.start();
                // Se queda esperando a que se conecte un cliente, cuando se conecta lo agrega al array de sockets y le inicia un hilo
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    public static KeyPair generarLlaves() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator= KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair pair = keyPairGenerator.generateKeyPair();

        return pair;
    }

    public void enviarLlave(Socket socket, PublicKey publicaServer) throws IOException {
        byte[] publicKeyBytes = publicKey.getEncoded();
        OutputStream outputStream = socket.getOutputStream();
        outputStream.write(publicKeyBytes);
    }

    public PublicKey recibirLlave(Socket cliente) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        InputStream inputStream = cliente.getInputStream();
        byte[] publicKeyBytes = new byte[2048];
        inputStream.read(publicKeyBytes);

        // Convierte los bytes en una clave pública
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    public boolean verificarMensaje(Mensaje mensaje, Socket cliente) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        boolean autenticado = false;
        System.out.println("entro verificacion");

        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        Cipher decryptCipher2 = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, clients.get(cliente));

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] mensajeDesencriptadoByte = decryptCipher.doFinal(mensaje.getMensajeEncriptado());
        String mensajeDesencriptado = new String(mensajeDesencriptadoByte, StandardCharsets.UTF_8);

        byte[] mensajeHasheadoByte = decryptCipher2.doFinal(mensaje.getMensajeHasheado());
        String mensajeHasheado = new String(mensajeHasheadoByte, StandardCharsets.UTF_8);

        byte[] mensajeDesencriptadoHasheadoByte = digest.digest(mensajeDesencriptado.getBytes(StandardCharsets.UTF_8));
        String mensajeDesencriptadoHasheado = new String(mensajeDesencriptadoHasheadoByte, StandardCharsets.UTF_8);

        if (mensajeHasheado.equals(mensajeDesencriptadoHasheado)){
            System.out.println("Mensaje recibido: " + new String(mensajeDesencriptado));
            autenticado = true;
        }
        return autenticado;
    }

    public void broadcastMessage(byte[] message, InetAddress ipEnvio) {
        for (Map.Entry<Socket, PublicKey> client: clients.entrySet()) {
            try {
                if (client.getKey().getInetAddress() != ipEnvio){
                    OutputStream outputStream = client.getKey().getOutputStream();
                    outputStream.write(message);
                    // Se envia en broadcast el mensaje a todos los clientes menos al que lo envio
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private class ClientHandler implements Runnable {
        private Socket clientSocket;

        public ClientHandler(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
            try {
                ObjectInputStream inputStream = new ObjectInputStream(clientSocket.getInputStream());

                while (true) {
                    boolean autenticado = false;

                    Object object = inputStream.readObject();
                    Mensaje mensajeRecibido = (Mensaje) object;

                    String mensajeDesencriptado = new String(mensajeRecibido.getMensajeEncriptado(), StandardCharsets.UTF_8);
                    String mensajeDesencriptado2 = new String(mensajeRecibido.getMensajeHasheado(), StandardCharsets.UTF_8);

                    System.out.println(mensajeDesencriptado);
                    System.out.println(mensajeDesencriptado2);

                    autenticado = verificarMensaje(mensajeRecibido, clientSocket);


                    //broadcastMessage(message, clientSocket.getInetAddress());
                }

                /*clients.remove(clientSocket);
                System.out.println("Cliente desconectado: " + clientSocket.getInetAddress().getHostAddress());
                clientSocket.close();
                */

            } catch (Throwable e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        TCPServer server = new TCPServer();
        server.start(2006);
    }
}