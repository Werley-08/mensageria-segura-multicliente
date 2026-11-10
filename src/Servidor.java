import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;

public final class Servidor {
    private static final int MAX_CLIENTES = 100;
    private final Map<UUID, Sessao> sessoes = new HashMap<>();
    private final PrivateKey chaveRsa;
    private final X509Certificate certificado;

    private Servidor(String arquivoPkcs12, String senha) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(Path.of(arquivoPkcs12))) {
            ks.load(in, senha.toCharArray());
        }
        chaveRsa = (PrivateKey) ks.getKey("servidor", senha.toCharArray());
        certificado = (X509Certificate) ks.getCertificate("servidor");
        if (chaveRsa == null || certificado == null || !"RSA".equals(chaveRsa.getAlgorithm()))
            throw new GeneralSecurityException("Keystore RSA inválido");
    }

    public static void main(String[] args) throws Exception {
        int porta = args.length > 0 ? Integer.parseInt(args[0]) : 5555;
        String keystore = args.length > 1 ? args[1] : "server.p12";
        String senha = System.getenv("RELAY_KEYSTORE_PASSWORD");
        if (senha == null || senha.isBlank()) {
            System.err.println("Defina RELAY_KEYSTORE_PASSWORD antes de iniciar o servidor.");
            return;
        }
        new Servidor(keystore, senha).executar(porta);
    }

    private void executar(int porta) throws IOException {
        try (ServerSocket servidor = new ServerSocket(porta)) {
            System.out.println("Servidor relay em TCP " + porta + " (máximo " + MAX_CLIENTES + " clientes).");
            while (true) {
                Socket socket = servidor.accept();
                Thread t = new Thread(() -> atender(socket), "cliente-" + socket.getPort());
                t.setDaemon(true);
                t.start();
            }
        }
    }

    private void atender(Socket socket) {
        Sessao atual = null;
        try (socket;
             DataInputStream entrada = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
             DataOutputStream saida = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()))) {
            socket.setSoTimeout(10000);
            byte[] primeiro = Protocolo.ler(entrada);
            if (primeiro.length != 49 || primeiro[0] != Protocolo.HELLO)
                throw new IOException("Handshake inicial inválido");
            ByteBuffer b = Protocolo.buffer(primeiro);
            b.get();
            UUID id = Protocolo.lerUuid(b);
            if (id.version() != 4) throw new IOException("É necessário UUID v4");
            byte[] pk = new byte[32]; b.get(pk);
            Criptografia.importarX25519(pk);
            byte[] saltHandshake = Criptografia.aleatorios(16);
            byte[] pkServidorEfemera = Criptografia.publicaRaw(Criptografia.gerarX25519().getPublic());
            atual = new Sessao(id, pk, pkServidorEfemera, saltHandshake, socket, saida);
            synchronized (sessoes) {
                if (sessoes.size() >= MAX_CLIENTES || sessoes.containsKey(id))
                    throw new IOException("Capacidade esgotada ou client_id duplicado");
                atual.enviarAck();
                sessoes.put(id, atual);
                for (Sessao outro : new ArrayList<>(sessoes.values())) {
                    if (outro == atual) continue;
                    byte[] saltPar = Criptografia.aleatorios(16);
                    atual.enviarOnline(outro, saltPar);
                    try {
                        outro.enviarOnline(atual, saltPar);
                    } catch (IOException | GeneralSecurityException erro) {
                        outro.fechar();
                    }
                }
            }
            socket.setSoTimeout(0);
            System.out.println("Conectado: " + id);
            while (true) {
                byte[] quadro = Protocolo.ler(entrada);
                if (quadro[0] != Protocolo.E2E || quadro.length < Protocolo.TAMANHO_E2E_MINIMO
                        || quadro.length > Protocolo.TAMANHO_E2E_MINIMO + Protocolo.MAX_TEXTO)
                    throw new IOException("Frame E2E inválido");
                ByteBuffer cabecalho = Protocolo.buffer(quadro);
                cabecalho.position(1 + 12);
                UUID remetente = Protocolo.lerUuid(cabecalho);
                UUID destinatario = Protocolo.lerUuid(cabecalho);
                long seqNo = cabecalho.getLong();
                if (!remetente.equals(id)) throw new IOException("Remetente não corresponde à sessão");
                atual.seqRecv = seqNo;
                Sessao destino;
                synchronized (sessoes) {
                    destino = sessoes.get(destinatario);
                }
                if (destino != null) {
                    try {
                        destino.enviar(quadro);
                        System.out.println("Relay " + id + " -> " + destinatario + ": " + quadro.length + " B");
                    } catch (IOException erro) {
                        destino.fechar();
                    }
                } else {
                    System.out.println("Destinatário desconectado: " + destinatario);
                }
            }
        } catch (EOFException e) {
        } catch (Exception e) {
            System.out.println("Conexão rejeitada/encerrada: " + e.getMessage());
        } finally {
            if (atual != null) {
                synchronized (sessoes) {
                    if (sessoes.remove(atual.id, atual)) {
                        System.out.println("Desconectado: " + atual.id);
                        for (Sessao outro : new ArrayList<>(sessoes.values())) {
                            try {
                                outro.enviarOffline(atual.id);
                            } catch (Exception e) {
                                outro.fechar();
                            }
                        }
                    }
                }
            }
        }
    }

    private final class Sessao {
        final UUID id;
        final byte[] pk, pkServidorEfemera, saltHandshake;
        final Socket socket;
        final DataOutputStream saida;
        long seqAdmin = 0;
        volatile long seqRecv = -1;

        Sessao(UUID id, byte[] pk, byte[] pkServidorEfemera, byte[] saltHandshake, Socket socket, DataOutputStream saida) {
            this.id = id;
            this.pk = pk.clone();
            this.pkServidorEfemera = pkServidorEfemera.clone();
            this.saltHandshake = saltHandshake.clone();
            this.socket = socket;
            this.saida = saida;
        }

        synchronized void enviar(byte[] frame) throws IOException {
            Protocolo.enviar(saida, frame);
        }

        synchronized void enviarAck() throws GeneralSecurityException, IOException {
            byte[] cert;
            try { cert = certificado.getEncoded(); }
            catch (java.security.cert.CertificateEncodingException e) {
                throw new GeneralSecurityException("Certificado inválido", e);
            }
            byte[] material = Criptografia.materialHandshake(pkServidorEfemera, pk, id, saltHandshake);
            byte[] assinatura = Criptografia.assinar(chaveRsa, material);
            byte[] corpo = ByteBuffer.allocate(32 + 4 + cert.length + 16 + 2 + assinatura.length)
                    .put(pkServidorEfemera).putInt(cert.length).put(cert).put(saltHandshake)
                    .putShort((short) assinatura.length).put(assinatura).array();
            enviar(Protocolo.montar(Protocolo.HELLO_ACK, corpo));
        }

        synchronized void enviarOnline(Sessao peer, byte[] saltPar)
                throws GeneralSecurityException, IOException {
            long seq = seqAdmin++;
            byte[] assinatura = Criptografia.assinar(chaveRsa,
                    Criptografia.materialOnline(id, seq, saltHandshake, peer.id, peer.pk, saltPar));
            byte[] corpo = ByteBuffer.allocate(8 + 16 + 32 + 16 + 2 + assinatura.length)
                    .putLong(seq).put(Protocolo.uuidBytes(peer.id)).put(peer.pk)
                    .put(saltPar).putShort((short) assinatura.length).put(assinatura).array();
            enviar(Protocolo.montar(Protocolo.PEER_ONLINE, corpo));
        }

        synchronized void enviarOffline(UUID peer) throws GeneralSecurityException, IOException {
            long seq = seqAdmin++;
            byte[] assinatura = Criptografia.assinar(chaveRsa,
                    Criptografia.materialOffline(id, seq, saltHandshake, peer));
            byte[] corpo = ByteBuffer.allocate(8 + 16 + 2 + assinatura.length)
                    .putLong(seq).put(Protocolo.uuidBytes(peer)).putShort((short) assinatura.length)
                    .put(assinatura).array();
            enviar(Protocolo.montar(Protocolo.PEER_OFFLINE, corpo));
        }

        void fechar() {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }
}
