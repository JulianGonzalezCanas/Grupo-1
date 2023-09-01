import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class HiloEnvio implements Runnable {

    private Socket socketCliente;
    private byte[] serverPub;
    private PrivateKey clientPriv;

    public HiloEnvio(Socket socketCliente, byte[] serverPub, PrivateKey clientPriv) {
        this.socketCliente = socketCliente;
        this.serverPub = serverPub;
        this.clientPriv = clientPriv;
    }

    @Override
    public void run() {
        try {
            PrintWriter salida = new PrintWriter(socketCliente.getOutputStream(), true);

            BufferedReader entradaUsuario = new BufferedReader(new InputStreamReader(System.in));

            String mensaje;

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeyRecreated = new X509EncodedKeySpec(serverPub);


            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, keyFactory.generatePublic(publicKeyRecreated));

            Cipher encryptCipher2 = Cipher.getInstance("RSA");
            encryptCipher2.init(Cipher.ENCRYPT_MODE, clientPriv);


            while (true) {
                System.out.println("Entro hilo envio");
                mensaje = entradaUsuario.readLine();

                // mensaje encriptado con publica de server
                byte[] mensajeBytes = mensaje.getBytes(StandardCharsets.UTF_8);
                byte[] mensajeBytesEncripted = encryptCipher.doFinal(mensajeBytes);

                // mensaje hasheado y encriptado con privada de cliente
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] digest = md.digest(mensaje.getBytes(StandardCharsets.UTF_8));
                String sha256 = DatatypeConverter.printHexBinary(digest).toLowerCase();

                byte[] sha256Bytes = sha256.getBytes(StandardCharsets.UTF_8);
                byte[] mensajeHashEncripted = encryptCipher.doFinal(sha256Bytes);

                // combinacion de mensajes y envio
                Mensaje mensajeCompleto = new Mensaje(mensajeBytesEncripted, mensajeHashEncripted);

                salida.println(mensajeCompleto);

                if (mensaje.equalsIgnoreCase("fin")) {
                    break;
                }
            }
            salida.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }
}