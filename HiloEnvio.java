import javax.crypto.*;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class HiloEnvio implements Runnable {

    private Socket socketCliente;
    private PublicKey serverPublicKey;
    private PrivateKey privateKey;
    private SecretKey secretKey;

    public HiloEnvio(Socket socketCliente, PublicKey publicKey, PrivateKey privateKey, SecretKey secretKey) {
        this.socketCliente = socketCliente;
        this.serverPublicKey = publicKey;
        this.privateKey = privateKey;
        this.secretKey = secretKey;
    }

    @Override
    public void run() {
        try {
            ObjectOutputStream outputStream = new ObjectOutputStream(socketCliente.getOutputStream());

            BufferedReader entradaUsuario = new BufferedReader(new InputStreamReader(System.in));

            String mensaje;

            byte[] mensajeEncriptadoSimetrica;
            byte[] mensajeHasheado;

            while (true) {
                mensaje = entradaUsuario.readLine();

                mensajeEncriptadoSimetrica = encriptarMensaje(mensaje, secretKey);
                mensajeHasheado = hashearMensajeEncriptar(mensaje, privateKey);
                Mensaje mensajeCompleto = new Mensaje(mensajeEncriptadoSimetrica, mensajeHasheado);

                outputStream.writeObject(mensajeCompleto);
                if (mensaje.equalsIgnoreCase("fin")) {
                    break;
                }
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    public byte[] encriptarMensaje(String mensaje, SecretKey keySym) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] dataInBytes = mensaje.getBytes();
        Cipher encryptionCipher;
        encryptionCipher = Cipher.getInstance("AES");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, keySym);
        byte[] encryptedBytes = encryptionCipher.doFinal(dataInBytes);

        return encryptedBytes;
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