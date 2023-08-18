import java.net.*;
import java.io.*;

public class TCPClient {
    public static void main(String[] args)  throws IOException {
        Socket socketCliente = null;

        try {
            socketCliente = new Socket("172.16.255.150", 2006);

        } catch (IOException e) {
            System.err.println("No puede establer canales de E/S para la conexion");
            System.exit(-1);
        }

        Thread hiloEscucha = new Thread(new HiloRecibo(socketCliente));


        Thread hiloEnvio = new Thread(new HiloEnvio(socketCliente));

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