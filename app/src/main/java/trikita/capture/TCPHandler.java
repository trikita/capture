package trikita.capture;

import android.util.Log;
import android.util.Pair;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class TCPHandler {
    private static final String TAG = "TCPHandler";

    public static final byte TCP_HEADER_LEN = 20;   // 20 bytes
    public static final byte TCP_FLAG_FIN = 0x01;
    public static final byte TCP_FLAG_SYN = 0x02;
    public static final byte TCP_FLAG_RST = 0x04;
    public static final byte TCP_FLAG_PSH = 0x08;
    public static final byte TCP_FLAG_ACK = 0x10;
    public static final byte TCP_FLAG_URG = 0x20;

    private boolean isFIN(byte b) { return (b & TCP_FLAG_FIN) == TCP_FLAG_FIN; }
    private boolean isSYN(byte b) { return (b & TCP_FLAG_SYN) == TCP_FLAG_SYN; }
    private boolean isRST(byte b) { return (b & TCP_FLAG_RST) == TCP_FLAG_RST; }
    private boolean isPSH(byte b) { return (b & TCP_FLAG_PSH) == TCP_FLAG_PSH; }
    private boolean isACK(byte b) { return (b & TCP_FLAG_ACK) == TCP_FLAG_ACK; }
    private boolean isURG(byte b) { return (b & TCP_FLAG_URG) == TCP_FLAG_URG; }


    private Random mRandom = new Random();

    private final Selector mSelector;
    private final VPNCaptureService mVPNService;
    private final VPNThread mVPNThread;

    private Map<Pair<InetSocketAddress, InetSocketAddress>, TCB> mSockets = new HashMap<>();

    public TCPHandler(Selector mSelector, VPNCaptureService svc, VPNThread thread) {
        this.mSelector = mSelector;
        this.mVPNService = svc;
        this.mVPNThread= thread;
    }

    // Unwraps raw data from a valid outgoing TCP packet and sends to the net
    public void processInput(InetAddress srcAddress, InetAddress dstAddress, ByteBuffer ip) throws IOException {
        Log.d(TAG, "processInput()");
        int srcPort = (ip.getShort() & 0xffff);
        int dstPort = (ip.getShort() & 0xffff);
        long seqNum = (ip.getInt() & 0xffffffffL);
        long ackNum = (ip.getInt() & 0xffffffffL);
        Log.d(TAG, "srcPort=" + srcPort + ", dstPort=" + dstPort + ", seq=" + seqNum + ", ack=" + ackNum);

        int chunk = (ip.getShort() & 0xffff);
        byte headerLen = (byte) ((byte) (chunk >> 12) * 4);

        ip.position(ip.position() + headerLen - 14);

        Pair<InetSocketAddress, InetSocketAddress> key =
                new Pair<>(new InetSocketAddress(srcAddress, srcPort),
                        new InetSocketAddress(dstAddress, dstPort));
        if (!mSockets.containsKey(key)) {
            if (isSYN((byte) chunk)) {
                Log.d(TAG, "SYN TCP packet");
                startConnection(ip, key, seqNum, ackNum);
            } else {
                Log.d(TAG, "Unknown outgoing TCP packet");
                resetSource(ip, key, ackNum);
            }
        } else if (isSYN((byte) chunk)) {
            Log.d(TAG, "Duplicate SYN TCP packet");
            resetDuplicateSYN(ip, key, seqNum);
        } else if (isACK((byte) chunk)) {
            Log.d(TAG, "ACK TCP packet");
            processACK(ip, key, seqNum, ackNum);
        } else {
            Log.d(TAG, "not a SYN TCP packet");
        }
    }

    private void processACK(ByteBuffer ip, Pair<InetSocketAddress, InetSocketAddress> key, long seq, long ack) throws IOException {
        TCB tcb = mSockets.get(key);
        if (tcb.getStatus() == TCB.TCBStatus.SYN_RECEIVED) {
            tcb.setStatus(TCB.TCBStatus.ESTABLISHED);
            tcb.setSelectionKey(tcb.getSocket().register(mSelector, SelectionKey.OP_READ, tcb));
        } else if (tcb.getStatus() == TCB.TCBStatus.LAST_ACK) {
            tcb.closeSocket();
            mSockets.remove(tcb);
            return;
        }

        int payloadSize = ip.remaining();

        if (payloadSize == 0) {
            return; // Zero length ACK
        }

        while (ip.hasRemaining()) {
            tcb.getSocket().write(ip); // TODO check IOException
        }

        tcb.setAckLocal(seq + payloadSize);
        tcb.setAckRemote(ack);

        ip.clear();
        IPHandler.fillHeader(ip, IPHandler.IP_HEADER_LEN, TCP_HEADER_LEN, IPHandler.TCP_PROTOCOL, key.second, key.first);
        fillHeader(ip, key.second, key.first, tcb.getSeqLocal(), tcb.getAckLocal(),
                TCP_HEADER_LEN, TCP_FLAG_ACK, 0);
        ip.flip();
        mVPNThread.addToOutput(ip);
    }

    private void resetDuplicateSYN(ByteBuffer buffer, Pair<InetSocketAddress, InetSocketAddress> tcbKey, long seq) {
        TCB tcb = mSockets.get(tcbKey);
        if (tcb.getStatus() == TCB.TCBStatus.SYN_SENT) {
            tcb.setAckLocal(seq + 1);
            return;
        }
        // TODO sort of resetSource() like sendRST() from LocalVPN
    }

    private void startConnection(ByteBuffer buffer, Pair<InetSocketAddress, InetSocketAddress> tcbKey, long seq, long ack) {
        try {
            SocketChannel socket = SocketChannel.open();
            socket.configureBlocking(false);

            Log.d(TAG, "start connection " + "seq dst="+seq+ " seq src=" + (seq+1) + " ack dst=" + ack);
            TCB tcb = new TCB(mRandom.nextInt(Short.MAX_VALUE + 1), seq, seq + 1, ack, socket);
            tcb.setUniqueKey(tcbKey);

            mSockets.put(tcbKey, tcb);

            mVPNService.protect(socket.socket());

            Log.d(TAG, "Connecting..");
            socket.connect(tcbKey.second);

            if (socket.finishConnect()) {
                Log.d(TAG, "Immediate connect finished\n");
                handleFinishConnect(tcb, buffer);
                tcb.setSeqLocal(tcb.getSeqLocal()+1);
            } else {
                Log.d(TAG, "Immediate connect failed, trying select()\n");
                tcb.setStatus(TCB.TCBStatus.SYN_SENT);
                tcb.setSelectionKey(socket.register(mSelector, SelectionKey.OP_CONNECT, tcb));
            }
        } catch (IOException e) {
            e.printStackTrace();
            mSockets.get(tcbKey).closeSocket();
            mSockets.remove(tcbKey);
        }
    }

    private void handleFinishConnect(TCB tcb, ByteBuffer buffer) {
        Pair<InetSocketAddress, InetSocketAddress> tcbKey = tcb.getUniqueKey();
        // simulate receiving SYN-ACK from the net if connection is established immediately
        tcb.setStatus(TCB.TCBStatus.SYN_RECEIVED);
        buffer.clear();
        IPHandler.fillHeader(buffer, IPHandler.IP_HEADER_LEN, TCP_HEADER_LEN, IPHandler.TCP_PROTOCOL, tcbKey.second, tcbKey.first);
        Log.d(TAG, "finish connection " + tcb.getSeqLocal() + " " + tcb.getAckLocal());
        fillHeader(buffer, tcbKey.second, tcbKey.first, tcb.getSeqLocal(), tcb.getAckLocal(),
                TCP_HEADER_LEN, (byte) (TCP_FLAG_SYN|TCP_FLAG_ACK), 0);
        buffer.flip();
        Utils.hexdump(buffer, buffer.remaining());

        tcb.setSeqLocal(tcb.getSeqLocal()+1);     // SYN counts as a byte
        mVPNThread.addToOutput(buffer);         // write to VPN fd
    }

    private void resetSource(ByteBuffer buffer, Pair<InetSocketAddress, InetSocketAddress> tcbKey, long ackNum) {
        Log.d(TAG, "resetSource()");
        buffer.clear();
        IPHandler.fillHeader(buffer, IPHandler.IP_HEADER_LEN, TCP_HEADER_LEN, IPHandler.TCP_PROTOCOL, tcbKey.first, tcbKey.second);
        fillHeader(buffer, tcbKey.first, tcbKey.second, 0, ackNum, TCP_HEADER_LEN, TCP_FLAG_RST, 0);
        buffer.flip();
        Utils.hexdump(buffer, buffer.remaining());

        mVPNThread.addToOutput(buffer);
    }

    public static void fillHeader(ByteBuffer buf, InetSocketAddress src, InetSocketAddress dst,
                                  long seqNum, long ackNum, byte headerLen, byte flags, int payloadSize) {
        // move position to the beginning of TCP header
        buf.position(IPHandler.IP_HEADER_LEN);

        buf.putShort((short) src.getPort());
        buf.putShort((short) dst.getPort());
        buf.putInt((int) seqNum);
        buf.putInt((int) ackNum);
        buf.put((byte) ((headerLen/4) << 4));
        buf.put(flags);
        buf.putShort((short) 0xffff);    // FIXME: window size
        buf.putShort((short) 0);    // Checksum
        buf.putShort((short) 0);    // FIXME: urgent pointer
        // TODO: options, padding

        buf.position(IPHandler.IP_HEADER_LEN);
        Utils.updateTCPChecksum(buf, src.getAddress().getAddress(), dst.getAddress().getAddress(), headerLen, payloadSize);
    }

    public void processConnect(SelectionKey key) {
        Log.d(TAG, "Selector connect finished\n");
        handleFinishConnect((TCB) key.attachment(), ByteBuffer.allocate(0x10000));
        key.interestOps(SelectionKey.OP_READ);
    }

    public ByteBuffer processOutput(SelectionKey key, ByteBuffer buffer) throws IOException {
        TCB tcb = (TCB) key.attachment();
        Pair<InetSocketAddress, InetSocketAddress> tcbKey = tcb.getUniqueKey();

        buffer.position(buffer.position() + TCP_HEADER_LEN);
        int n = tcb.getSocket().read(buffer);
        if (n <= 0) {
            // TODO: close socket
            Log.d(TAG, "close socket");
            return null;
        }
        int end = buffer.position();

        buffer.clear();
        IPHandler.fillHeader(buffer, IPHandler.IP_HEADER_LEN, (short) (TCP_HEADER_LEN + n), IPHandler.TCP_PROTOCOL, tcbKey.second, tcbKey.first);
        fillHeader(buffer, tcbKey.second, tcbKey.first, tcb.getSeqLocal(), tcb.getAckLocal(),
                TCP_HEADER_LEN, (byte) (TCP_FLAG_PSH|TCP_FLAG_ACK), n);
        buffer.position(end);
        buffer.flip();

        tcb.setSeqLocal(tcb.getSeqLocal() + n);
        return buffer;
    }
}
