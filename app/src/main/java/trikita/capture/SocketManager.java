package trikita.capture;

import android.util.Log;
import android.util.Pair;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.sql.DatabaseMetaData;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;

public class SocketManager {

    private static final String TAG = "SocketManager";

    private final Selector mSelector;
    private final VPNThread mVPN;

    private final IPUtils.IPHeader mIPHeader = new IPUtils.IPHeader();
    private final IPUtils.UDPHeader mUDPHeader = new IPUtils.UDPHeader();
    private final IPUtils.TCPHeader mTCPHeader = new IPUtils.TCPHeader();

    private final Random mRandom = new Random();
    private final ByteBuffer mIPOutBuffer = ByteBuffer.allocate(IPUtils.MAX_DATAGRAM_SIZE);

    private final Map<IPUtils.SocketID, DatagramChannel> mUDPSockets = new HashMap<>();
    private final Map<IPUtils.SocketID, TCB> mTCPSockets = new HashMap<>();

    public SocketManager(VPNThread vpn) throws IOException {
        mVPN = vpn;
        mSelector = Selector.open();
    }

    public void processIPOut(ByteBuffer ip) {
        Log.d(TAG, IPUtils.hexdump("RAW OUTGOING PACKET: ", ip));
        IPUtils.IPHeader.parse(ip, mIPHeader);
        Log.d(TAG, mIPHeader.toString());
        if (mIPHeader.protocol == IPUtils.PROTO_TCP) {
            IPUtils.TCPHeader.parse(ip, mTCPHeader);
            processTCPOut(mIPHeader, mTCPHeader, ip);
        } else if (mIPHeader.protocol == IPUtils.PROTO_UDP) {
            IPUtils.UDPHeader.parse(ip, mUDPHeader);
            processUDPOut(mIPHeader, mUDPHeader, ip);
        } else {
            IPUtils.panic("unsupported protocol: " + mIPHeader.protocol);
            Log.d(TAG, mIPHeader.toString());
            Log.d(TAG, IPUtils.hexdump("RAW IP DATA: ", ip));
        }
    }

    private void processTCPOut(IPUtils.IPHeader ipHeader, IPUtils.TCPHeader tcpHeader, ByteBuffer data) {
        IPUtils.SocketID id = IPUtils.SocketID.fromTCP(ipHeader, tcpHeader);
        TCB tcb = mTCPSockets.get(id);
        if (tcb == null) {
            // Expect the first packet to have a SYN flag (e.g. socket doing connect())
            if ((tcpHeader.flags & IPUtils.TCPHeader.TCP_FLAG_SYN) != 0) {
                if ((tcb = startTCPConnect(id, ipHeader, tcpHeader)) != null) {
                    mTCPSockets.put(id, tcb);
                }
            } else {
                // Reset source
            }
        } else if ((tcpHeader.flags & IPUtils.TCPHeader.TCP_FLAG_SYN) != 0) {
            // Duplicate SYN (connection retry)
        } else if ((tcpHeader.flags & IPUtils.TCPHeader.TCP_FLAG_ACK) != 0) {
            // Process outgoing ACK (e.g. when data is written to socket)
            processTCPAckOut(tcb, tcpHeader, data);
        } else {
            IPUtils.panic("unexpected tcp flags: " + tcpHeader.flags);
        }
    }

    private TCB startTCPConnect(IPUtils.SocketID id, IPUtils.IPHeader ipHeader, IPUtils.TCPHeader tcpHeader) {
        TCB tcb = null;
        SocketChannel socket = null;
        try {
            socket = SocketChannel.open();
            socket.configureBlocking(false);
            mVPN.protect(socket.socket());

            tcb = new TCB(id, socket, mRandom.nextInt(Short.MAX_VALUE + 1), tcpHeader.seq,
                    tcpHeader.seq + 1, tcpHeader.ack);

            socket.connect(id.dst());
            if (socket.finishConnect()) {
                Log.d(TAG, "TCP connect finished immediately");
                finishTCPConnect(tcb, mIPOutBuffer);
                tcb.setSelectionKey(socket.register(mSelector, SelectionKey.OP_READ, tcb));
            } else {
                Log.d(TAG, "TCP connect started");
                tcb.setSelectionKey(socket.register(mSelector, SelectionKey.OP_CONNECT, tcb));
            }
            return tcb;
        } catch (IOException e) {
            e.printStackTrace();
            if (tcb != null) {
                mTCPSockets.remove(tcb);
            }
            if (socket != null) {
                try { socket.close(); } catch (IOException ignore) { ignore.printStackTrace(); }
            }
            return null;
        }
    }

    private void finishTCPConnect(TCB tcb, ByteBuffer ip) {
        IPUtils.SocketID id = tcb.getID();
        tcb.setStatus(TCB.SYN_RECEIVED);

        ip.clear();

        ip.position(IPUtils.IPHeader.DEFAULT_LENGTH);
        IPUtils.TCPHeader.fill(ip, id.dst(), id.src(), tcb.getLocalSeq(), tcb.getLocalAck(),
                IPUtils.TCPHeader.TCP_FLAG_SYN | IPUtils.TCPHeader.TCP_FLAG_ACK, 0);

        ip.position(0);
        IPUtils.IPHeader.fill(ip, id.dst(), id.src(), IPUtils.PROTO_TCP, IPUtils.TCPHeader.DEFAULT_LENGTH);

        ip.position(0);
        ip.limit(IPUtils.IPHeader.DEFAULT_LENGTH + IPUtils.TCPHeader.DEFAULT_LENGTH);
        tcb.advanceSeq(1); // SYN counts as a byte
        mVPN.write(ip);
    }

    private void processTCPAckOut(TCB tcb, IPUtils.TCPHeader tcpHeader, ByteBuffer data) {
        try {
            if (tcb.getStatus() == TCB.SYN_RECEIVED) {
                tcb.setStatus(TCB.ESTABLISHED);
                tcb.setSelectionKey(tcb.getSocket().register(mSelector, SelectionKey.OP_READ, tcb));
            } else if (tcb.getStatus() == TCB.LAST_ACK) {
                tcb.closeSocket();
                mTCPSockets.remove(tcb);
                return;
            }

            int payloadSize = data.remaining();
            if (payloadSize == 0) {
                return; // Zero length ACK
            }

            while (data.hasRemaining()) {
                tcb.getSocket().write(data);
            }

            tcb.setLocalAck(tcpHeader.seq + payloadSize);
            tcb.setRemoteAck(tcpHeader.ack);

            // Respond with fake "ACK" to move the window

            IPUtils.SocketID id = tcb.getID();
            ByteBuffer ip = mIPOutBuffer;
            ip.clear();
            ip.position(IPUtils.IPHeader.DEFAULT_LENGTH);
            IPUtils.TCPHeader.fill(ip, id.dst(), id.src(), tcb.getLocalSeq(), tcb.getLocalAck(),
                    IPUtils.TCPHeader.TCP_FLAG_ACK, 0);

            ip.position(0);
            IPUtils.IPHeader.fill(ip, id.dst(), id.src(), IPUtils.PROTO_TCP, IPUtils.TCPHeader.DEFAULT_LENGTH);

            ip.position(0);
            ip.limit(IPUtils.IPHeader.DEFAULT_LENGTH + IPUtils.TCPHeader.DEFAULT_LENGTH);
            mVPN.write(ip);
        } catch (ClosedChannelException e) {
            e.printStackTrace();
            tcb.closeSocket();
            mTCPSockets.remove(tcb);
        } catch (IOException e) {
            e.printStackTrace();
            tcb.closeSocket();
            mTCPSockets.remove(tcb);
        }
    }

    private void processUDPOut(IPUtils.IPHeader ipHeader, IPUtils.UDPHeader udpHeader, ByteBuffer data) {
        try {
            IPUtils.SocketID id = IPUtils.SocketID.fromUDP(ipHeader, udpHeader);
            DatagramChannel socket = mUDPSockets.get(id);
            if (socket == null) {
                Log.d(TAG, "Open datagram channel");
                socket = DatagramChannel.open();
                socket.connect(id.dst());
                socket.configureBlocking(false);
                socket.register(mSelector, SelectionKey.OP_READ, id);
                // TODO: might need to bind to fix android bug with incorrect src ip address
                mVPN.protect(socket.socket());
                mUDPSockets.put(id, socket);
            }
            int n = socket.write(data);
            if (data.hasRemaining()) {
                IPUtils.panic("udp write failed: written " + n + ", remaining " + data.remaining());
            }
        } catch (IOException e) {
            IPUtils.panic("udp output exception: " + e.getMessage());
        }
    }

    public void select(ByteBuffer ip) throws IOException {
        mSelector.select(10);
        Iterator it = mSelector.selectedKeys().iterator();
        while (it.hasNext()) {
            SelectionKey k = (SelectionKey) it.next();
            it.remove();
            if (!k.isValid()) {
                continue;
            }
            if (k.channel() instanceof DatagramChannel) {
                if (k.isReadable()) {
                    processUDPIn(k, ip);
                }
            } else if (k.channel() instanceof SocketChannel) {
                if (k.isConnectable()) {
                    processTCPConnect(k, ip);
                }
                if (k.isReadable()) {
                    processTCPIn(k, ip);
                }
            }
        }
    }

    private void processUDPIn(SelectionKey k, ByteBuffer ip) {
        try {
            ip.clear();
            ip.position(IPUtils.IPHeader.DEFAULT_LENGTH + IPUtils.UDPHeader.DEFAULT_LENGTH);
            int n = 0;
            IPUtils.SocketID id = (IPUtils.SocketID) k.attachment();
            n = ((DatagramChannel) k.channel()).read(ip);
            if (n <= 0) {
                IPUtils.panic("failed reading from udp socket: " + n);
                return;
            }
            ip.flip();
            ip.position(IPUtils.IPHeader.DEFAULT_LENGTH);
            IPUtils.UDPHeader.fill(ip, id.dst(), id.src(), n);
            ip.position(0);
            IPUtils.IPHeader.fill(ip, id.dst(), id.src(),
                    IPUtils.PROTO_UDP, IPUtils.UDPHeader.DEFAULT_LENGTH + n);
            ip.position(0);
            mVPN.write(ip);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void processTCPConnect(SelectionKey k, ByteBuffer ip) {
        Log.d(TAG, "TCP connect finished for " + k);
        finishTCPConnect((TCB) k.attachment(), mIPOutBuffer);
        k.interestOps(SelectionKey.OP_READ);
    }

    private void processTCPIn(SelectionKey k, ByteBuffer ip) {
        try {
            TCB tcb = (TCB) k.attachment();
            IPUtils.SocketID id = tcb.getID();
            ip.position(IPUtils.IPHeader.DEFAULT_LENGTH + IPUtils.TCPHeader.DEFAULT_LENGTH);
            int n = 0;
            n = tcb.getSocket().read(ip);
            if (n <= 0) {
                IPUtils.panic("tcp read error: " + n);
                return;
            }
            ip.clear();
            ip.position(IPUtils.IPHeader.DEFAULT_LENGTH);
            IPUtils.TCPHeader.fill(ip, id.dst(), id.src(), tcb.getLocalSeq(), tcb.getLocalAck(),
                    IPUtils.TCPHeader.TCP_FLAG_PSH | IPUtils.TCPHeader.TCP_FLAG_ACK, n);

            ip.position(0);
            IPUtils.IPHeader.fill(ip, id.dst(), id.src(), IPUtils.PROTO_TCP, IPUtils.TCPHeader.DEFAULT_LENGTH + n);
            ip.position(0);
            ip.limit(IPUtils.IPHeader.DEFAULT_LENGTH + IPUtils.TCPHeader.DEFAULT_LENGTH + n);
            tcb.advanceSeq(n);
            mVPN.write(ip);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
