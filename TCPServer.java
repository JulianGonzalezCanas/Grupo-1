import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public class TCPServer {

    private List<Socket> clients;

    public TCPServer() {
        clients = new ArrayList<>();
    }

    public void start(int port) {
        try {
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Servidor iniciado en el puerto " + port);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                clients.add(clientSocket);
                System.out.println("Nuevo cliente conectado: " + clientSocket.getInetAddress().getHostAddress());

                ClientHandler clientHandler = new ClientHandler(clientSocket);
                Thread clientThread = new Thread(clientHandler);
                clientThread.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void broadcastMessage(byte[] message, InetAddress ipEnvio) {
        for (Socket client : clients) {
            try {
                if (client.getInetAddress() != ipEnvio){
                    OutputStream outputStream = client.getOutputStream();
                    outputStream.write(message);
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
                        break; // El cliente ha cerrado la conexión
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
        server.start(2611);
    }
}