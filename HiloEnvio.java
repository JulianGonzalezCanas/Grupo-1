import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class HiloEnvio implements Runnable {

    private Socket socketCliente;

    private PublicKey serverPublicKey;
    private PrivateKey privateKey;

    public HiloEnvio(Socket socketCliente, PublicKey publicKey, PrivateKey privateKey) {
        this.socketCliente = socketCliente;
        this.serverPublicKey = publicKey;
        this.privateKey = privateKey;
    }

    @Override
    public void run() {
        try {
            ObjectOutputStream outputStream = new ObjectOutputStream(socketCliente.getOutputStream());

            BufferedReader entradaUsuario = new BufferedReader(new InputStreamReader(System.in));

            String mensaje;

            byte[] mensajeEncriptadoPublicaServer;
            byte[] mensajeHasheado;

            while (true) {
                mensaje = entradaUsuario.readLine();

                mensajeEncriptadoPublicaServer = encriptarMensaje(mensaje, serverPublicKey);
                mensajeHasheado = hashearMensajeEncriptar(mensaje, privateKey);
                Mensaje mensajeCompleto = new Mensaje(mensajeEncriptadoPublicaServer, mensajeHasheado);

                outputStream.writeObject(mensajeCompleto);
                if (mensaje.equalsIgnoreCase("fin")) {
                    break;
                }
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    public byte[] encriptarMensaje(String mensaje, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] mensajeBytes = mensaje.getBytes(StandardCharsets.UTF_8);
        byte[] mensajeEncriptado = encryptCipher.doFinal(mensajeBytes);

        return mensajeEncriptado;
    }

    public byte[] hashearMensajeEncriptar(String mensaje, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] mensajeHasheado = digest.digest(mensaje.getBytes(StandardCharsets.UTF_8));

        byte[] mensajeEncriptado = encryptCipher.doFinal(mensajeHasheado);

        return mensajeEncriptado;
    }
}