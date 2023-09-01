public class Mensaje {
    private byte[] m1;
    private byte[] m2;

    public Mensaje(byte[] m1, byte[] m2) {
        this.m1 = m1;
        this.m2 = m2;
    }

    public byte[] getM1() {
        return m1;
    }

    public void setM1(byte[] m1) {
        this.m1 = m1;
    }

    public byte[] getM2() {
        return m2;
    }

    public void setM2(byte[] m2) {
        this.m2 = m2;
    }
}
