import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
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
    private HashMap<Socket, ObjectOutputStream> clientsOutputs;

    private static KeyPair keyPair;

    static {
        try {
            keyPair = generarLlaves();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static SecretKey symKey;

    static {
        try {
            symKey = generarSimetrica();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static PublicKey publicKey = keyPair.getPublic();
    private static PrivateKey privateKey = keyPair.getPrivate();

    public TCPServer(){
        clients = new HashMap<>();
        clientsOutputs = new HashMap<>();
    }

    public void start(int port) {
        try {
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Servidor iniciado en el puerto " + port);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                PublicKey publicaCliente = null;

                enviarLlave(clientSocket);
                publicaCliente = recibirLlave(clientSocket);
                clients.put(clientSocket, publicaCliente);

                enviarSimetrica(clientSocket);

                System.out.println("Nuevo cliente conectado: " + clientSocket.getInetAddress().getHostAddress());

                ClientHandler clientHandler = new ClientHandler(clientSocket);
                Thread clientThread = new Thread(clientHandler);
                clientThread.start();
                // Se queda esperando a que se conecte un cliente, cuando se conecta lo agrega al array de sockets y le inicia un hilo
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyPair generarLlaves() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator= KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair pair = keyPairGenerator.generateKeyPair();

        return pair;
    }

    public static SecretKey generarSimetrica() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    public void enviarLlave(Socket socket) throws IOException {
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

    public void enviarSimetrica(Socket socket) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
        byte[] llaveSimBytes = symKey.getEncoded();

        byte[] llaveEncriptada = encriptarLlaveSim(llaveSimBytes, clients.get(socket));
        byte[] llaveHasheada = hashearLlaveSim(llaveSimBytes);

        Mensaje llaveCombinacion = new Mensaje(llaveEncriptada, llaveHasheada);
        outputStream.writeObject(llaveCombinacion);
    }

    public String verificarMensaje(Mensaje mensaje, Socket cliente) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher decryptionCipher = Cipher.getInstance("AES");
        decryptionCipher.init(Cipher.DECRYPT_MODE, symKey);

        byte[] decryptedBytes = decryptionCipher.doFinal(mensaje.getMensajeEncriptado());
        String mensajeDesencriptado = new String(decryptedBytes, StandardCharsets.UTF_8);

        Cipher decryptCipher2 = Cipher.getInstance("RSA");
        decryptCipher2.init(Cipher.DECRYPT_MODE, clients.get(cliente));

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] mensajeHasheadoByte = decryptCipher2.doFinal(mensaje.getMensajeHasheado());
        String mensajeHasheado = new String(mensajeHasheadoByte, StandardCharsets.UTF_8);

        byte[] mensajeDesencriptadoHasheadoByte = digest.digest(mensajeDesencriptado.getBytes(StandardCharsets.UTF_8));
        String mensajeDesencriptadoHasheado = new String(mensajeDesencriptadoHasheadoByte, StandardCharsets.UTF_8);

        if (mensajeHasheado.equals(mensajeDesencriptadoHasheado)){
            System.out.println("Mensaje recibido: " + new String(mensajeDesencriptado));
            return mensajeDesencriptado;
        }
        return null;
    }

    public void broadcastMessage(String mensaje, InetAddress ipEnvio) {

        byte[] mensajeEncriptadoSimetrica;
        byte[] mensajeHasheado;
        for (Map.Entry<Socket, PublicKey> client: clients.entrySet()) {
            try {


                    mensajeEncriptadoSimetrica = encriptarMensaje(mensaje, symKey);
                    mensajeHasheado = hashearMensajeEncriptar(mensaje);
                    Mensaje mensajeCompleto = new Mensaje(mensajeEncriptadoSimetrica, mensajeHasheado);

                if (!clientsOutputs.containsKey(client.getKey())){
                    clientsOutputs.put(client.getKey(), new ObjectOutputStream(client.getKey().getOutputStream()));
                    clientsOutputs.get(client.getKey()).writeObject(mensajeCompleto);
                } else{
                    clientsOutputs.get(client.getKey()).writeObject(mensajeCompleto);
                }
                    // Se envia en broadcast el mensaje a todos los clientes menos al que lo envio

            } catch (Throwable e) {
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

                    Object object = inputStream.readObject();
                    Mensaje mensajeRecibido = (Mensaje) object;
                    String mensajeAutenticado;
                    mensajeAutenticado = verificarMensaje(mensajeRecibido, clientSocket);

                    if (mensajeAutenticado != null){
                        broadcastMessage(mensajeAutenticado, clientSocket.getInetAddress());
                    } else{
                        break;
                    }

                }

                clients.remove(clientSocket);
                System.out.println("Cliente desconectado: " + clientSocket.getInetAddress().getHostAddress());
                clientSocket.close();


            } catch (Throwable e) {
                e.printStackTrace();
            }
        }
    }

    public byte[] encriptarMensaje(String mensaje, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance("AES");
        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] mensajeBytes = mensaje.getBytes(StandardCharsets.UTF_8);
        byte[] mensajeEncriptado = encryptCipher.doFinal(mensajeBytes);

        return mensajeEncriptado;
    }

    public byte[] hashearMensajeEncriptar(String mensaje) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] mensajeHasheado = digest.digest(mensaje.getBytes(StandardCharsets.UTF_8));

        byte[] mensajeEncriptado = encryptCipher.doFinal(mensajeHasheado);

        return mensajeEncriptado;
    }

    public byte[] encriptarLlaveSim(byte[] llaveSimBytes, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] llaveEncriptada = encryptCipher.doFinal(llaveSimBytes);
        return llaveEncriptada;
    }

    public byte[] hashearLlaveSim(byte[] llaveSimBytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] llaveHasheada = digest.digest(llaveSimBytes);

        byte[] llaveHasheadaEncriptada = encryptCipher.doFinal(llaveHasheada);

        return llaveHasheadaEncriptada;
    }

    public static void main(String[] args) {
        TCPServer server = new TCPServer();
        server.start(2921);
    }
}