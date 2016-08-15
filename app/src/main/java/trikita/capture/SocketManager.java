package trikita.capture;

import android.util.Log;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
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
                    processTCPConnect(k);
                }
                if (k.isReadable()) {
                    processTCPIn(k, ip);
                }
            }
        }
    }

    //
    // IP
    //

    public void processIPOut(ByteBuffer ip) {
        IPUtils.IPHeader.parse(ip, mIPHeader);
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

    private void processIPIn(ByteBuffer ip, IPUtils.SocketID id, int n, TCB tcb, int flags) {
        int proto;
        ip.position(IPUtils.IPHeader.DEFAULT_LENGTH);
        if (tcb != null) {
            IPUtils.TCPHeader.fill(ip, id.dst(), id.src(), tcb.getLocalSeq(), tcb.getLocalAck(), flags, n);
            n = n + IPUtils.TCPHeader.DEFAULT_LENGTH;
            proto = IPUtils.PROTO_TCP;
        } else {
            IPUtils.UDPHeader.fill(ip, id.dst(), id.src(), n);
            n = n + IPUtils.UDPHeader.DEFAULT_LENGTH;
            proto = IPUtils.PROTO_UDP;
        }
        ip.position(0);
        IPUtils.IPHeader.fill(ip, id.dst(), id.src(), proto, n);
        ip.position(0);
        ip.limit(IPUtils.IPHeader.DEFAULT_LENGTH + n);
//        Log.d(TAG, IPUtils.hexdump("IP IN: ", ip));
        mVPN.write(ip);
    }

    //
    // UDP
    //

    private void processUDPOut(IPUtils.IPHeader ipHeader, IPUtils.UDPHeader udpHeader, ByteBuffer data) {
        try {
            IPUtils.SocketID id = IPUtils.SocketID.fromUDP(ipHeader, udpHeader);
            DatagramChannel socket = mUDPSockets.get(id);
            if (socket == null) {
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
            processIPIn(ip, id, n, null, 0);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    //
    // TCP
    //

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
//                resetTCP(id, tcpHeader.seq+1);
            }
        } else if ((tcpHeader.flags & IPUtils.TCPHeader.TCP_FLAG_SYN) != 0) {
            processTCPDuplicateSynOut(id, tcpHeader);
        } else if ((tcpHeader.flags & IPUtils.TCPHeader.TCP_FLAG_RST) != 0) {
            closeTCP(id);
        } else if ((tcpHeader.flags & IPUtils.TCPHeader.TCP_FLAG_FIN) != 0) {
            processTCPFinOut(tcb, tcpHeader);
        } else if ((tcpHeader.flags & IPUtils.TCPHeader.TCP_FLAG_ACK) != 0) {
            processTCPAckOut(tcb, tcpHeader, data);
        } else {
            IPUtils.panic("unexpected tcp flags: " + tcpHeader.flags);
        }
    }

    private void processTCPFinOut(TCB tcb, IPUtils.TCPHeader tcpHeader) {
        Log.d(TAG, "FIN out " + tcb.getID());
        tcb.setLocalAck(tcpHeader.seq + 1);
        tcb.setRemoteAck(tcpHeader.ack);
        tcb.setStatus(TCB.LAST_ACK);
        processIPIn(mIPOutBuffer, tcb.getID(), 0, tcb, IPUtils.TCPHeader.TCP_FLAG_ACK | IPUtils.TCPHeader.TCP_FLAG_FIN);
        tcb.advanceSeq(1);
    }

    private void closeTCP(IPUtils.SocketID id) {
        Log.d(TAG, "connection reset by peer:" + id);
        TCB tcb = mTCPSockets.get(id);
        if (tcb != null) {
            Log.d(TAG, "close tcb" + tcb.getID());
            tcb.closeSocket();
        }
        mTCPSockets.remove(id);
    }

    private void processTCPDuplicateSynOut(IPUtils.SocketID id, IPUtils.TCPHeader tcpHeader) {
        Log.d(TAG, "duplicate SYN: " + id);
        TCB tcb = mTCPSockets.get(id);
        if (tcb != null && tcb.getStatus() == TCB.SYN_SENT) {
            tcb.setLocalAck(tcpHeader.seq + 1);
        } else {
            resetTCP(id, tcpHeader.seq + 1);
        }
    }

    private void resetTCP(IPUtils.SocketID id, int defaultAck) {
        Log.d(TAG, "RST: " + id);
        TCB tcb = mTCPSockets.get(id);
        if (tcb == null) {
            tcb = new TCB(id, null, 0, 0, defaultAck, 0);
        }
        mIPOutBuffer.clear();
        processIPIn(mIPOutBuffer, id, 0, tcb, IPUtils.TCPHeader.TCP_FLAG_RST);
        closeTCP(id);
        IPUtils.panic("resetTCP");
    }

    private TCB startTCPConnect(IPUtils.SocketID id, IPUtils.IPHeader ipHeader, IPUtils.TCPHeader tcpHeader) {
        Log.d(TAG, "first SYN: " + id);
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
            resetTCP(tcb.getID(), 0);
            if (tcb != null) {
                mTCPSockets.remove(tcb.getID());
            }
            if (socket != null) {
                try { socket.close(); } catch (IOException ignore) { ignore.printStackTrace(); }
            }
            return null;
        }
    }

    private void finishTCPConnect(TCB tcb, ByteBuffer ip) {
        Log.d(TAG, "SYN+ACK: " + tcb.getID());
        try {
            if (tcb.getSocket().finishConnect()) {
                IPUtils.SocketID id = tcb.getID();
                tcb.setStatus(TCB.SYN_RECEIVED);

                Log.d(TAG, "finishTCPConnect" + tcb.getID());

                // Reply with SYN+ACK
                ip.clear();
                processIPIn(ip, id, 0, tcb, IPUtils.TCPHeader.TCP_FLAG_SYN | IPUtils.TCPHeader.TCP_FLAG_ACK);
                tcb.advanceSeq(1); // SYN counts as a byte
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void processTCPAckOut(TCB tcb, IPUtils.TCPHeader tcpHeader, ByteBuffer data) {
        Log.d(TAG, "ACK outgoing: " + tcb.getID());
        try {
            if (tcb.getStatus() == TCB.SYN_RECEIVED) {
                tcb.setStatus(TCB.ESTABLISHED);
                tcb.setSelectionKey(tcb.getSocket().register(mSelector, SelectionKey.OP_READ, tcb));
            } else if (tcb.getStatus() == TCB.LAST_ACK) {
                closeTCP(tcb.getID());
                return;
            }

            int payloadSize = data.remaining();
            if (payloadSize == 0) {
                return; // Zero length ACK
            }

            while (data.hasRemaining()) {
                tcb.getSocket().write(data);
            }

            // Respond with fake "ACK" to move the window
            tcb.setLocalAck(tcpHeader.seq + payloadSize);
            tcb.setRemoteAck(tcpHeader.ack);
            mIPOutBuffer.clear();
            processIPIn(mIPOutBuffer, tcb.getID(), 0, tcb, IPUtils.TCPHeader.TCP_FLAG_ACK);
        } catch (IOException e) {
            e.printStackTrace();
            resetTCP(tcb.getID(), 0);
        }
    }

    private void processTCPConnect(SelectionKey k) {
        Log.d(TAG, "TCP connect finished for " + k);
        finishTCPConnect((TCB) k.attachment(), mIPOutBuffer);
        k.interestOps(SelectionKey.OP_READ);
    }

    private void processTCPIn(SelectionKey k, ByteBuffer ip) {
        TCB tcb = (TCB) k.attachment();
        Log.d(TAG, "ACK incoming: " + tcb.getID() + " status = " + tcb.getStatus());
        try {
            ip.position(IPUtils.IPHeader.DEFAULT_LENGTH + IPUtils.TCPHeader.DEFAULT_LENGTH);
            if (!tcb.getSocket().isConnected()) {
                Log.d(TAG, "socket not connected: " + tcb.getID());
                return;
            }
            int n = tcb.getSocket().read(ip);
            if (n <= 0) {
                Log.d(TAG, "socket closed from the remote end");
                k.interestOps(0);
//                if (tcb.getStatus() != TCB.CLOSE_WAIT) {
//                    Log.d(TAG, "close wait");
//                    processIPIn(mIPOutBuffer, tcb.getID(), 0, tcb, IPUtils.TCPHeader.TCP_FLAG_FIN | IPUtils.TCPHeader.TCP_FLAG_ACK);
//                    tcb.advanceSeq(1); // FIN counts as byte
//                    resetTCP(tcb.getID(), 0);
//                    return;
//                }
                Log.d(TAG, "close wait");
                tcb.setStatus(TCB.LAST_ACK);
                processIPIn(mIPOutBuffer, tcb.getID(), 0, tcb, IPUtils.TCPHeader.TCP_FLAG_FIN | IPUtils.TCPHeader.TCP_FLAG_ACK);
                tcb.advanceSeq(1); // FIN counts as byte
                return;
            }
            ip.clear();
            processIPIn(ip, tcb.getID(), n, tcb, IPUtils.TCPHeader.TCP_FLAG_PSH | IPUtils.TCPHeader.TCP_FLAG_ACK);
            tcb.advanceSeq(n);
        } catch (IOException e) {
            e.printStackTrace();
            resetTCP(tcb.getID(), 0);
        }
    }
}
