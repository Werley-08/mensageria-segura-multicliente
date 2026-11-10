import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

public final class Cliente {
    private final UUID id;
    private final Map<UUID, Par> pares = new ConcurrentHashMap<>();
    private final AtomicBoolean conectado = new AtomicBoolean(true);
    private final KeyPair efemero;
    private final X509Certificate certificadoPinado;
    private byte[] saltHandshake;
    private long ultimoSeqAdmin = -1;
    private Socket socket;
    private DataOutputStream saida;

    Cliente(String arquivoCertificado, UUID id) throws Exception {
        if (id.version() != 4) throw new IllegalArgumentException("O client_id deve ser UUID v4");
        this.id = id;
        efemero = Criptografia.gerarX25519();
        try (InputStream in = Files.newInputStream(Path.of(arquivoCertificado))) {
            certificadoPinado = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
        certificadoPinado.checkValidity();
        certificadoPinado.verify(certificadoPinado.getPublicKey());
    }

    public static void main(String[] args) throws Exception {
        String host = args.length > 0 ? args[0] : "localhost";
        int porta = args.length > 1 ? Integer.parseInt(args[1]) : 5555;
        String crt = args.length > 2 ? args[2] : "server.crt";
        UUID id = args.length > 3 ? UUID.fromString(args[3]) : UUID.randomUUID();
        try {
            new Cliente(crt, id).executar(host, porta);
        } catch (GeneralSecurityException e) {
            System.err.println("Falha na autenticação do servidor: " + e.getMessage());
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Falha de conexão: " + e.getMessage());
            System.exit(1);
        }
    }

    private void executar(String host, int porta) throws Exception {
        try (Socket s = new Socket(host, porta);
             DataInputStream entrada = new DataInputStream(new BufferedInputStream(s.getInputStream()));
             DataOutputStream out = new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
             Scanner terminal = new Scanner(System.in, java.nio.charset.StandardCharsets.UTF_8)) {
            socket = s;
            saida = out;
            s.setSoTimeout(10000);
            byte[] pk = Criptografia.publicaRaw(efemero.getPublic());
            byte[] hello = ByteBuffer.allocate(1 + 16 + 32).put(Protocolo.HELLO)
                    .put(Protocolo.uuidBytes(id)).put(pk).array();
            Protocolo.enviar(saida, hello);
            validarHandshake(Protocolo.ler(entrada), pk);
            s.setSoTimeout(0);
            System.out.println("Conexão autenticada com o servidor. Seu client_id: " + id);
            System.out.println("Comandos: lista | enviar UUID mensagem | teste-bitflip UUID mensagem | "
                    + "teste-replay UUID mensagem | teste-framing | sair");

            Thread recebimento = new Thread(() -> {
                try {
                    while (conectado.get()) {
                        receber(Protocolo.ler(entrada));
                    }
                } catch (Exception e) {
                    if (conectado.get())
                        System.out.println("Conexão encerrada: " + e.getMessage());
                } finally {
                    boolean inesperado = conectado.getAndSet(false);
                    try { s.close(); } catch (IOException ignored) {}
                    if (inesperado) {
                        System.out.println("Cliente encerrado.");
                        System.exit(0);
                    }
                }
            }, "recebimento");
            recebimento.setDaemon(true);
            recebimento.start();

            while (conectado.get() && terminal.hasNextLine()) {
                String linha = terminal.nextLine().trim();
                if (linha.equals("sair")) break;
                if (linha.equals("lista")) {
                    if (pares.isEmpty()) System.out.println("Nenhum cliente conectado.");
                    else pares.keySet().forEach(System.out::println);
                } else if (linha.equals("teste-framing")) {
                    synchronized (saida) { saida.writeInt(Protocolo.MAX_FRAME + 1); saida.flush(); }
                    System.out.println("Prefixo inválido enviado; servidor deve desconectar.");
                    break;
                } else if (linha.startsWith("enviar ") || linha.startsWith("teste-bitflip ")
                        || linha.startsWith("teste-replay ")) {
                    try {
                        String[] partes = linha.split(" ", 3);
                        if (partes.length < 3) throw new IllegalArgumentException("Informe UUID e mensagem");
                        UUID destino = UUID.fromString(partes[1]);
                        Par p = pares.get(destino);
                        if (p == null) throw new IllegalArgumentException("Destinatário ausente na lista");
                        byte[] frame = p.montarMensagem(partes[2]);
                        if (partes[0].equals("teste-bitflip")) {
                            frame[frame.length - 1] ^= 1;
                            Protocolo.enviar(saida, frame);
                            System.out.println("Enviado frame adulterado (deve falhar a tag GCM).");
                        } else if (partes[0].equals("teste-replay")) {
                            Protocolo.enviar(saida, frame);
                            Protocolo.enviar(saida, frame);
                            System.out.println("Mesmo frame enviado duas vezes (segundo deve ser rejeitado).");
                        } else {
                            Protocolo.enviar(saida, frame);
                            System.out.println("Mensagem E2E enviada (" + frame.length + " bytes cifrados no frame).");
                        }
                    } catch (Exception e) {
                        System.out.println("Comando rejeitado: " + e.getMessage());
                    }
                } else if (!linha.isBlank()) {
                    System.out.println("Comando desconhecido. Use 'lista', 'enviar UUID texto' ou 'sair'.");
                }
            }
            conectado.set(false);
        } finally {
            conectado.set(false);
            pares.clear();
        }
    }

    private void validarHandshake(byte[] frame, byte[] minhaPk) throws Exception {
        if (frame[0] != Protocolo.HELLO_ACK) throw new GeneralSecurityException("Resposta ao handshake inválida");
        ByteBuffer b = Protocolo.buffer(frame);
        b.get();
        if (b.remaining() < 32 + 4) throw new GeneralSecurityException("ACK incompleto");
        byte[] pkServidorEfemera = new byte[32]; b.get(pkServidorEfemera);
        Criptografia.importarX25519(pkServidorEfemera);
        int certLen = b.getInt();
        if (certLen < 1 || certLen > 8192 || b.remaining() < certLen + 18)
            throw new GeneralSecurityException("Comprimento do certificado inválido");
        byte[] certificadoRecebido = new byte[certLen]; b.get(certificadoRecebido);
        if (!MessageDigest.isEqual(certificadoPinado.getEncoded(), certificadoRecebido))
            throw new GeneralSecurityException("Certificado diferente do server.crt pinado");
        saltHandshake = new byte[16]; b.get(saltHandshake);
        byte[] assinatura = lerAssinatura(b);
        if (!Criptografia.verificar(certificadoPinado.getPublicKey(),
                Criptografia.materialHandshake(pkServidorEfemera, minhaPk, id, saltHandshake), assinatura))
            throw new GeneralSecurityException("Assinatura RSA-PSS do handshake inválida");
    }

    private static byte[] lerAssinatura(ByteBuffer b) throws GeneralSecurityException {
        if (b.remaining() < 2) throw new GeneralSecurityException("Assinatura ausente");
        int tamanho = Short.toUnsignedInt(b.getShort());
        if (tamanho < 256 || tamanho > 1024 || b.remaining() != tamanho)
            throw new GeneralSecurityException("Tamanho/posição da assinatura inválidos");
        byte[] assinatura = new byte[tamanho]; b.get(assinatura);
        return assinatura;
    }

    private void receber(byte[] frame) throws Exception {
        ByteBuffer b = Protocolo.buffer(frame);
        byte tipo = b.get();
        if (tipo == Protocolo.PEER_ONLINE) {
            if (b.remaining() < 8 + 16 + 32 + 16 + 2) throw new GeneralSecurityException("PEER_ONLINE incompleto");
            long seq = b.getLong();
            UUID peerId = Protocolo.lerUuid(b);
            byte[] pk = new byte[32], saltPar = new byte[16];
            b.get(pk); b.get(saltPar);
            byte[] assinatura = lerAssinatura(b);
            if (seq <= ultimoSeqAdmin || !Criptografia.verificar(certificadoPinado.getPublicKey(),
                    Criptografia.materialOnline(id, seq, saltHandshake, peerId, pk, saltPar), assinatura))
                throw new GeneralSecurityException("Atualização PEER_ONLINE adulterada ou repetida");
            ultimoSeqAdmin = seq;
            if (peerId.equals(id)) throw new GeneralSecurityException("Peer com identidade local");
            Par estado = new Par(id, peerId, efemero.getPrivate(), pk, saltPar);
            pares.put(peerId, estado);
            System.out.println("Novo cliente: " + peerId);
        } else if (tipo == Protocolo.PEER_OFFLINE) {
            if (b.remaining() < 8 + 16 + 2) throw new GeneralSecurityException("PEER_OFFLINE incompleto");
            long seq = b.getLong();
            UUID peerId = Protocolo.lerUuid(b);
            byte[] assinatura = lerAssinatura(b);
            if (seq <= ultimoSeqAdmin || !Criptografia.verificar(certificadoPinado.getPublicKey(),
                    Criptografia.materialOffline(id, seq, saltHandshake, peerId), assinatura))
                throw new GeneralSecurityException("Atualização PEER_OFFLINE adulterada ou repetida");
            ultimoSeqAdmin = seq;
            pares.remove(peerId);
            System.out.println("Cliente desconectou: " + peerId);
        } else if (tipo == Protocolo.E2E) {
            if (frame.length < Protocolo.TAMANHO_E2E_MINIMO)
                throw new IOException("Tamanho E2E inválido");
            b.position(1 + 12);
            UUID peer = Protocolo.lerUuid(b);
            Par estado = pares.get(peer);
            if (estado == null) {
                System.out.println("Rejeitado E2E: remetente não registrado");
                return;
            }
            try {
                String mensagem = estado.lerMensagem(frame);
                System.out.println("Mensagem de " + peer + ": " + mensagem);
            } catch (GeneralSecurityException e) {
                System.out.println("Mensagem E2E rejeitada: " + e.getMessage());
            }
        } else {
            throw new IOException("Tipo de frame inesperado: " + tipo);
        }
    }
}
