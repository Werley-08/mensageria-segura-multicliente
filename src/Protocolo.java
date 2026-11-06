import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.UUID;

final class Protocolo {
    private Protocolo() {}

    static final int MAX_FRAME = 16_384;
    static final int MAX_TEXTO = 4096;
    static final byte HELLO = 1, HELLO_ACK = 2, PEER_ONLINE = 3,
                      E2E = 4, PEER_OFFLINE = 5;
    static final int TAMANHO_E2E_MINIMO = 1 + 12 + 16 + 16 + 8 + 16;

    static byte[] ler(DataInputStream in) throws IOException {
        int tamanho = in.readInt();
        if (tamanho < 1 || tamanho > MAX_FRAME) {
            throw new IOException("Tamanho de frame inválido: " + tamanho);
        }
        byte[] quadro = new byte[tamanho];
        in.readFully(quadro);
        return quadro;
    }

    static void enviar(DataOutputStream out, byte[] quadro) throws IOException {
        if (quadro.length < 1 || quadro.length > MAX_FRAME) {
            throw new IOException("Tamanho de frame fora dos limites");
        }
        synchronized (out) {
            out.writeInt(quadro.length);
            out.write(quadro);
            out.flush();
        }
    }

    static byte[] montar(byte tipo, byte[] dados) {
        return ByteBuffer.allocate(1 + dados.length).put(tipo).put(dados).array();
    }

    static UUID lerUuid(ByteBuffer b) {
        return new UUID(b.getLong(), b.getLong());
    }

    static void escreverUuid(ByteBuffer b, UUID id) {
        b.putLong(id.getMostSignificantBits()).putLong(id.getLeastSignificantBits());
    }

    static byte[] uuidBytes(UUID id) {
        ByteBuffer b = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN);
        escreverUuid(b, id);
        return b.array();
    }

    static byte[] longBytes(long valor) {
        return ByteBuffer.allocate(8).putLong(valor).array();
    }

    static ByteBuffer buffer(byte[] dados) {
        return ByteBuffer.wrap(dados).order(ByteOrder.BIG_ENDIAN);
    }
}
