import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.security.*;

public class TCPServer {

    private List<Socket> clients;
    private HashMap<InetAddress, byte[]> keys;

    public TCPServer() {
        clients = new ArrayList<>();
    }

    public void start(int port) {
        try {
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Servidor iniciado en el puerto " + port);

            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();

            while (true) {
                Socket clientSocket = serverSocket.accept();
                clients.add(clientSocket);
                byte[] clientPub = exchangeKeys(pair.getPublic(), clientSocket);
                keys.put(clientSocket.getInetAddress(), clientPub);
                System.out.println("Nuevo cliente conectado: " + clientSocket.getInetAddress().getHostAddress());

                ClientHandler clientHandler = new ClientHandler(clientSocket);
                Thread clientThread = new Thread(clientHandler);
                clientThread.start();
                // Se queda esperando a que se conecte un cliente, cuando se conecta lo agrega al array de sockets y le inicia un hilo
            }
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public byte[] exchangeKeys(PublicKey serverPub, Socket socketCliente) throws IOException {
        OutputStream outputStream = socketCliente.getOutputStream();
        outputStream.write(serverPub.getEncoded());

        BufferedReader entrada = new BufferedReader(new InputStreamReader(socketCliente.getInputStream()));
        String respuesta = entrada.readLine();
        byte[] publicKey = respuesta.getBytes();

        return publicKey;
    }

    public void broadcastMessage(byte[] message, InetAddress ipEnvio) {
        for (Socket client : clients) {
            try {
                if (client.getInetAddress() != ipEnvio){
                    OutputStream outputStream = client.getOutputStream();
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
                InputStream inputStream = clientSocket.getInputStream();

                while (true) {
                    byte[] buffer = new byte[1024];
                    int bytesRead = inputStream.read(buffer);
                    if (bytesRead == -1) {
                        break;
                    }

                    byte[] message = new byte[bytesRead];
                    System.arraycopy(buffer, 0, message, 0, bytesRead);
                    System.out.println("Mensaje recibido: " + new String(message));

                    broadcastMessage(message, clientSocket.getInetAddress());
                }

                clients.remove(clientSocket);
                System.out.println("Cliente desconectado: " + clientSocket.getInetAddress().getHostAddress());
                clientSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        TCPServer server = new TCPServer();
        server.start(2556);
    }
}