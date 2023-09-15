import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;

public class HiloRecibo implements Runnable {

    private Socket socketCliente;

    public HiloRecibo(Socket socketCliente) {
        this.socketCliente = socketCliente;
    }

    @Override
    public void run() {
        try {
            BufferedReader entrada = new BufferedReader(new InputStreamReader(socketCliente.getInputStream()));
            String respuesta;

            while ((respuesta = entrada.readLine()) != null) {
                System.out.println("Respuesta del servidor: " + respuesta);
            }

            entrada.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}