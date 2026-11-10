import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.UUID;

final class Par {
    final UUID meuId;
    final UUID outroId;
    final byte[] publicaPeer;
    private final byte[] enviarChave;
    private final byte[] receberChave;
    private final byte[] ivEnviar = Criptografia.aleatorios(4);
    private byte[] ivReceber = null;
    private long proximoSeq = 0;
    private long ultimoRecebido = -1;

    Par(UUID meuId, UUID outroId, PrivateKey privada, byte[] publicaPeer, byte[] salt)
            throws GeneralSecurityException {
        this.meuId = meuId;
        this.outroId = outroId;
        this.publicaPeer = publicaPeer.clone();
        byte[] segredo = Criptografia.ecdh(privada, publicaPeer);
        try {
            byte[] chaveA2B = Criptografia.hkdf(salt, segredo, "A2B");
            byte[] chaveB2A = Criptografia.hkdf(salt, segredo, "B2A");
            boolean souA = meuId.compareTo(outroId) < 0;
            enviarChave = souA ? chaveA2B : chaveB2A;
            receberChave = souA ? chaveB2A : chaveA2B;
        } finally {
            Arrays.fill(segredo, (byte) 0);
        }
    }

    synchronized byte[] montarMensagem(String mensagem) throws GeneralSecurityException {
        byte[] texto = mensagem.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (texto.length > Protocolo.MAX_TEXTO)
            throw new GeneralSecurityException("Limite de 4096 bytes por mensagem excedido");
        if (proximoSeq < 0 || proximoSeq == Long.MAX_VALUE)
            throw new GeneralSecurityException("Contador esgotado, reconecte");
        long seq = proximoSeq++;
        byte[] nonce = ByteBuffer.allocate(12).put(ivEnviar).putLong(seq).array();
        byte[] aad = ByteBuffer.allocate(40)
                .put(Protocolo.uuidBytes(meuId)).put(Protocolo.uuidBytes(outroId))
                .putLong(seq).array();
        byte[] criptograma = Criptografia.cifrar(enviarChave, nonce, aad, texto);
        return ByteBuffer.allocate(1 + 12 + 16 + 16 + 8 + criptograma.length)
                .put(Protocolo.E2E).put(nonce)
                .put(Protocolo.uuidBytes(meuId)).put(Protocolo.uuidBytes(outroId))
                .putLong(seq).put(criptograma).array();
    }

    synchronized String lerMensagem(byte[] quadro) throws GeneralSecurityException {
        if (quadro.length < Protocolo.TAMANHO_E2E_MINIMO || quadro.length >
                Protocolo.TAMANHO_E2E_MINIMO + Protocolo.MAX_TEXTO)
            throw new GeneralSecurityException("Frame E2E com tamanho inválido");
        ByteBuffer b = Protocolo.buffer(quadro);
        if (b.get() != Protocolo.E2E) throw new GeneralSecurityException("Tipo de frame inválido");
        byte[] nonce = new byte[12]; b.get(nonce);
        UUID sender = Protocolo.lerUuid(b);
        UUID recipient = Protocolo.lerUuid(b);
        long seq = b.getLong();
        if (!sender.equals(outroId) || !recipient.equals(meuId))
            throw new GeneralSecurityException("Identificadores E2E incorretos");
        if (seq < 0 || seq <= ultimoRecebido)
            throw new GeneralSecurityException("Replay ou contador inválido");
        if (ByteBuffer.wrap(nonce, 4, 8).getLong() != seq)
            throw new GeneralSecurityException("Nonce e seq_no divergentes");
        byte[] base = Arrays.copyOf(nonce, 4);
        if (ivReceber != null && !Arrays.equals(ivReceber, base))
            throw new GeneralSecurityException("IV base alterado durante a sessão");
        byte[] criptograma = new byte[b.remaining()]; b.get(criptograma);
        byte[] aad = ByteBuffer.allocate(40).put(Protocolo.uuidBytes(sender))
                .put(Protocolo.uuidBytes(recipient)).putLong(seq).array();
        byte[] texto = Criptografia.decifrar(receberChave, nonce, aad, criptograma);
        ultimoRecebido = seq;
        if (ivReceber == null) ivReceber = base;
        return new String(texto, java.nio.charset.StandardCharsets.UTF_8);
    }
}
