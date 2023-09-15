import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class HiloRecibo implements Runnable {

    private Socket socketCliente;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public HiloRecibo(Socket socketCliente, PublicKey publicKey, PrivateKey privateKey) {
        this.socketCliente = socketCliente;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    @Override
    public void run() {
        try {
            ObjectInputStream inputStream = new ObjectInputStream(socketCliente.getInputStream());

            while (true) {

                Object object = inputStream.readObject();
                Mensaje mensajeRecibido = (Mensaje) object;
                verificarMensaje(mensajeRecibido, socketCliente);
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    public void verificarMensaje(Mensaje mensaje, Socket cliente) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {

        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, this.privateKey);

        Cipher decryptCipher2 = Cipher.getInstance("RSA");
        decryptCipher2.init(Cipher.DECRYPT_MODE, this.publicKey);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] mensajeDesencriptadoByte = decryptCipher.doFinal(mensaje.getMensajeEncriptado());
        String mensajeDesencriptado = new String(mensajeDesencriptadoByte, StandardCharsets.UTF_8);

        byte[] mensajeHasheadoByte = decryptCipher2.doFinal(mensaje.getMensajeHasheado());
        String mensajeHasheado = new String(mensajeHasheadoByte, StandardCharsets.UTF_8);

        byte[] mensajeDesencriptadoHasheadoByte = digest.digest(mensajeDesencriptado.getBytes(StandardCharsets.UTF_8));
        String mensajeDesencriptadoHasheado = new String(mensajeDesencriptadoHasheadoByte, StandardCharsets.UTF_8);

        if (mensajeHasheado.equals(mensajeDesencriptadoHasheado)){
            System.out.println(new String(mensajeDesencriptado));
        }
    }
}