import java.io.Serializable;

public class Mensaje implements Serializable {
    private byte[] mensajeEncriptado;
    private byte[] mensajeHasheado;

    public Mensaje(byte[] mensajeEncriptado, byte[] mensajeHasheado) {
        this.mensajeEncriptado = mensajeEncriptado;
        this.mensajeHasheado = mensajeHasheado;
    }

    public byte[] getMensajeEncriptado() {
        return mensajeEncriptado;
    }

    public void setMensajeEncriptado(byte[] mensajeEncriptado) {
        this.mensajeEncriptado = mensajeEncriptado;
    }

    public byte[] getMensajeHasheado() {
        return mensajeHasheado;
    }

    public void setMensajeHasheado(byte[] mensajeHasheado) {
        this.mensajeHasheado = mensajeHasheado;
    }
}