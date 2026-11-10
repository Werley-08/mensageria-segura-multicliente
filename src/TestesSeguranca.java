import java.io.*;
import java.security.*;
import java.util.*;

public final class TestesSeguranca {
    private static int realizados = 0;
    private static void validar(boolean condicao, String nome) {
        if (!condicao) throw new AssertionError("FALHOU: " + nome);
        System.out.println("[OK] " + nome);
        realizados++;
    }
    private static boolean rejeita(RunnableTeste teste) {
        try { teste.rodar(); return false; } catch (Exception e) { return true; }
    }
    interface RunnableTeste { void rodar() throws Exception; }

    public static void main(String[] args) throws Exception {
        UUID a = UUID.randomUUID(), b = UUID.randomUUID();
        KeyPair alice = Criptografia.gerarX25519(), bob = Criptografia.gerarX25519();
        byte[] pka = Criptografia.publicaRaw(alice.getPublic());
        byte[] pkb = Criptografia.publicaRaw(bob.getPublic());
        validar(pka.length == 32 && pkb.length == 32, "X25519 públicas raw de 32 bytes");
        validar(Arrays.equals(Criptografia.ecdh(alice.getPrivate(), pkb),
                Criptografia.ecdh(bob.getPrivate(), pka)), "ECDH gera segredo igual nas duas pontas");

        byte[] salt = Criptografia.aleatorios(16);
        Par deA = new Par(a, b, alice.getPrivate(), pkb, salt);
        Par deB = new Par(b, a, bob.getPrivate(), pka, salt);
        byte[] ok = deA.montarMensagem("olá, E2E!");
        validar("olá, E2E!".equals(deB.lerMensagem(ok)), "AES-128-GCM ida: destinatário decifra");
        byte[] volta = deB.montarMensagem("resposta cifrada");
        validar("resposta cifrada".equals(deA.lerMensagem(volta)), "AES-128-GCM volta: destinatário decifra");
        validar(rejeita(() -> deB.lerMensagem(ok)), "Anti-replay: frame repetido rejeitado");

        byte[] adulterado = deA.montarMensagem("original");
        adulterado[adulterado.length - 1] ^= 1;
        validar(rejeita(() -> deB.lerMensagem(adulterado)), "Bitflip: tag GCM adulterada é rejeitada");
        byte[] validoAposBitflip = deA.montarMensagem("continua funcionando");
        validar("continua funcionando".equals(deB.lerMensagem(validoAposBitflip)),
                "Rejeição de bitflip não altera contador de recebimento");

        byte[] frameInvalido = new byte[4];
        java.nio.ByteBuffer.wrap(frameInvalido).putInt(Protocolo.MAX_FRAME + 1);
        validar(rejeita(() -> Protocolo.ler(new DataInputStream(new ByteArrayInputStream(frameInvalido)))),
                "Framing inválido: tamanho acima do limite rejeitado");
        validar(rejeita(() -> Protocolo.ler(new DataInputStream(new ByteArrayInputStream(
                new byte[] {0, 0, 0, 9, 1})))), "Framing truncado: conexão fecha com EOF");

        KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        byte[] pkServidor = Criptografia.publicaRaw(Criptografia.gerarX25519().getPublic());
        byte[] registro = Criptografia.materialHandshake(pkServidor, pka, a, salt);
        byte[] assinatura = Criptografia.assinar(rsa.getPrivate(), registro);
        validar(Criptografia.verificar(rsa.getPublic(), registro, assinatura),
                "RSA-PSS SHA-256 valida assinatura");
        registro[0] ^= 1;
        validar(!Criptografia.verificar(rsa.getPublic(), registro, assinatura),
                "RSA-PSS rejeita alteração no registro");
        System.out.println("\n" + realizados + " testes aprovados.");
    }
}
