package trikita.capture;

import android.util.Log;
import android.util.Pair;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class SocketManager {

    private static final String TAG = "SocketManager";

    private final Selector mSelector;
    private final VPNThread mVPN;

    private final IPUtils.IPHeader mIPHeader = new IPUtils.IPHeader();
    private final IPUtils.UDPHeader mUDPHeader = new IPUtils.UDPHeader();
    private final IPUtils.TCPHeader mTCPHeader = new IPUtils.TCPHeader();

    private final ByteBuffer mIPOutBuffer = ByteBuffer.allocate(IPUtils.MAX_DATAGRAM_SIZE);

    private final Map<IPUtils.SocketID, DatagramChannel> mUDPSockets = new HashMap<>();

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
            Log.d(TAG, mTCPHeader.toString());
            Log.d(TAG, IPUtils.hexdump("RAW TCP DATA: ", ip));
        } else if (mIPHeader.protocol == IPUtils.PROTO_UDP) {
            IPUtils.UDPHeader.parse(ip, mUDPHeader);
            processUDPOut(mIPHeader, mUDPHeader, ip);
        } else {
            IPUtils.panic("unsupported protocol: " + mIPHeader.protocol);
            Log.d(TAG, mIPHeader.toString());
            Log.d(TAG, IPUtils.hexdump("RAW IP DATA: ", ip));
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
    }

    private void processTCPIn(SelectionKey k, ByteBuffer ip) {
    }
}
