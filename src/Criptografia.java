import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.XECPublicKey;
import java.security.spec.*;
import java.util.Arrays;

final class Criptografia {
    private Criptografia() {}
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final PSSParameterSpec PSS = new PSSParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

    static byte[] aleatorios(int n) {
        byte[] valor = new byte[n];
        RANDOM.nextBytes(valor);
        return valor;
    }

    static KeyPair gerarX25519() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("X25519").generateKeyPair();
    }

    static byte[] publicaRaw(PublicKey chave) {
        byte[] big = ((XECPublicKey) chave).getU().toByteArray();
        byte[] raw = new byte[32];
        for (int i = 0; i < 32 && i < big.length; i++) {
            raw[i] = big[big.length - 1 - i];
        }
        return raw;
    }

    static PublicKey importarX25519(byte[] raw) throws GeneralSecurityException {
        if (raw.length != 32) throw new GeneralSecurityException("Chave X25519 não tem 32 bytes");
        byte[] big = raw.clone();
        for (int i = 0; i < 16; i++) {
            byte temp = big[i]; big[i] = big[31-i]; big[31-i] = temp;
        }
        return KeyFactory.getInstance("X25519").generatePublic(
                new XECPublicKeySpec(NamedParameterSpec.X25519, new BigInteger(1, big)));
    }

    static byte[] ecdh(PrivateKey privada, byte[] publicaRemota) throws GeneralSecurityException {
        KeyAgreement acordo = KeyAgreement.getInstance("X25519");
        acordo.init(privada);
        acordo.doPhase(importarX25519(publicaRemota), true);
        byte[] segredo = acordo.generateSecret();
        boolean zero = true;
        for (byte b : segredo) zero &= b == 0;
        if (zero) throw new GeneralSecurityException("Segredo X25519 inválido");
        return segredo;
    }

    static byte[] sha256(byte[] dados) throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-256").digest(dados);
    }

    static byte[] concatenar(byte[]... partes) {
        int total = 0;
        for (byte[] parte : partes) total += parte.length;
        ByteBuffer b = ByteBuffer.allocate(total);
        for (byte[] parte : partes) b.put(parte);
        return b.array();
    }

    static byte[] hkdf(byte[] salt, byte[] segredo, String label) throws GeneralSecurityException {
        if (salt.length != 16) throw new GeneralSecurityException("Salt deve ter 16 bytes");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(segredo);
        try {
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(label.getBytes(StandardCharsets.US_ASCII));
            mac.update((byte) 1);
            return Arrays.copyOf(mac.doFinal(), 16);
        } finally {
            Arrays.fill(prk, (byte) 0);
        }
    }

    static byte[] assinar(PrivateKey rsa, byte[] material) throws GeneralSecurityException {
        Signature s = Signature.getInstance("RSASSA-PSS");
        s.setParameter(PSS);
        s.initSign(rsa);
        s.update(sha256(material));
        return s.sign();
    }

    static boolean verificar(PublicKey rsa, byte[] material, byte[] assinatura)
            throws GeneralSecurityException {
        Signature s = Signature.getInstance("RSASSA-PSS");
        s.setParameter(PSS);
        s.initVerify(rsa);
        s.update(sha256(material));
        return s.verify(assinatura);
    }

    static byte[] cifrar(byte[] chave, byte[] nonce, byte[] aad, byte[] texto)
            throws GeneralSecurityException {
        if (chave.length != 16 || nonce.length != 12 || texto.length > Protocolo.MAX_TEXTO)
            throw new GeneralSecurityException("Parâmetros AES-GCM inválidos");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(chave, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(texto);
    }

    static byte[] decifrar(byte[] chave, byte[] nonce, byte[] aad, byte[] cifrado)
            throws GeneralSecurityException {
        if (chave.length != 16 || nonce.length != 12 || cifrado.length < 16 ||
                cifrado.length > Protocolo.MAX_TEXTO + 16)
            throw new GeneralSecurityException("Parâmetros AES-GCM inválidos");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(chave, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(cifrado);
    }

    static byte[] materialHandshake(byte[] pkServidorEfemera, byte[] pkCliente, java.util.UUID id, byte[] salt) {
        return concatenar(pkServidorEfemera, pkCliente, Protocolo.uuidBytes(id), salt);
    }

    static byte[] materialOnline(java.util.UUID destinatario, long seq, byte[] saltHandshake,
                                 java.util.UUID peer, byte[] pkPeer, byte[] saltPar) {
        return concatenar("PEER_ONLINE".getBytes(StandardCharsets.US_ASCII),
                Protocolo.uuidBytes(destinatario), Protocolo.longBytes(seq), saltHandshake,
                Protocolo.uuidBytes(peer), pkPeer, saltPar);
    }

    static byte[] materialOffline(java.util.UUID destinatario, long seq, byte[] saltHandshake,
                                  java.util.UUID peer) {
        return concatenar("PEER_OFFLINE".getBytes(StandardCharsets.US_ASCII),
                Protocolo.uuidBytes(destinatario), Protocolo.longBytes(seq), saltHandshake,
                Protocolo.uuidBytes(peer));
    }
}
