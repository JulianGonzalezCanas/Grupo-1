import java.net.*;
import java.io.*;

public class TCPClient {
    public static void main(String[] args)  throws IOException {
        Socket socketCliente = null;
        BufferedReader entrada = null;
        PrintWriter salida = null;

        try {
            socketCliente = new Socket("172.16.255.150", 2611);

            entrada = new BufferedReader(new InputStreamReader(socketCliente.getInputStream()));

            salida = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socketCliente.getOutputStream())),true);
        } catch (IOException e) {
            System.err.println("No puede establer canales de E/S para la conexion");
            System.exit(-1);
        }
        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

        String linea;

        try {
            while (true) {

                linea = stdIn.readLine();

                salida.println(linea);

                linea = entrada.readLine();
                System.out.println("Respuesta servidor: " + linea);

                if (linea.equals("Adios")) break;
            }
        } catch (IOException e) {
            System.out.println("IOException: " + e.getMessage());
        }


        salida.close();
        entrada.close();
        stdIn.close();
        socketCliente.close();
    }
}