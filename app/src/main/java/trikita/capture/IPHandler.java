package trikita.capture;

import android.util.Log;
import android.util.Pair;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;

public class IPHandler {

    private static final String TAG = "IPHandler";

    public static final int IP_PACKET_SIZE = 64 * 1024; // max possible packet size
    public static final byte IP4_VERSION = 4;       // IPv4
    public static final byte IP_HEADER_LEN = 20;    // 20 bytes
    public static final byte IP_TTL = 0x64;    // 100 sec
    public static final byte UDP_PROTOCOL = 0x11;   // 17
    public static final byte TCP_PROTOCOL = 0x06;   // 6

    private final Selector mSelector;
    private final UDPHandler mUDPHandler;
    private final TCPHandler mTCPHandler;

    public IPHandler(Selector selector, VPNCaptureService svc, VPNThread thread) {
        mSelector = selector;
        mUDPHandler = new UDPHandler(mSelector, svc);
        mTCPHandler = new TCPHandler(mSelector, svc, thread);
    }

    // Unwraps raw data from a valid outgoing IP packet and sends to the net
    public void processInput(ByteBuffer ip) throws IOException {
        Log.d(TAG, "processInput()");
        Log.d(TAG, "--- IP OUT ---");
        Utils.hexdump(ip, ip.remaining());

        byte header = ip.get();
        if ((header & 0xf0) != 0x40) {
            throw new IOException("not an IP packet header: " + header);
        }
        int headerLen = (header & 0x0f) * 4;
        ip.get(); // skip "Type of Service"
        int totalLength = ip.getShort() & 0xffff;
        ip.getInt();   // skipping till "Protocol"
        ip.get();   // skipping till "Protocol"
        short protocol = (short) (ip.get() & 0xff);

        if (protocol != TCP_PROTOCOL && protocol != UDP_PROTOCOL) {
            Log.d(TAG, "Unknown packet type");
            return;
        }
        ip.getShort();  // skip "Checksum"

        byte[] addr = new byte[4];
        for (int i = 0; i < addr.length; i++) {
            addr[i] = ip.get();
        }
        InetAddress srcAddress = InetAddress.getByAddress(addr);
        for (int i = 0; i < addr.length; i++) {
            addr[i] = ip.get();
        }
        InetAddress dstAddress = InetAddress.getByAddress(addr);

        // skip the rest of header bytes till data
        for (int i = 0; i < (headerLen - IP_HEADER_LEN); i++) {
            ip.get();
        }
        if (protocol == TCP_PROTOCOL) {    // TCP packet
            Log.d(TAG, "TCP packet detected: protocol=" + protocol);
            Utils.hexdump(ip, 64);
            mTCPHandler.processInput(srcAddress, dstAddress, ip);
        } else if (protocol == UDP_PROTOCOL) {     // UDP packet
            Log.d(TAG, "UDP packet detected: protocol=" + protocol);
            mUDPHandler.processInput(srcAddress, dstAddress, ip);
        }
    }

    // Wraps raw data from the net into a valid incoming IP packet
    public ByteBuffer processOutput(SelectionKey key) {
        ByteBuffer writeBuffer = ByteBuffer.allocate(IP_PACKET_SIZE);
        // leave bytes for IP
        writeBuffer.position(IP_HEADER_LEN);

        if (key.channel() instanceof DatagramChannel) {
            try {
                Pair<InetSocketAddress, InetSocketAddress> attachment = (Pair<InetSocketAddress, InetSocketAddress>) key.attachment();
                InetSocketAddress src = attachment.first;
                InetSocketAddress dst = attachment.second;
                byte numBytes = mUDPHandler.processOutput((DatagramChannel) key.channel(), writeBuffer, src.getPort(), dst.getPort());
                fillHeader(writeBuffer, IP_HEADER_LEN, numBytes, UDP_PROTOCOL, src, dst);

                writeBuffer.limit(IP_HEADER_LEN + numBytes);
                return writeBuffer;
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            try {
                return mTCPHandler.processOutput(key, writeBuffer);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    public static void fillHeader(ByteBuffer buf, byte headerLen, short dataLen, byte protocol,
                            InetSocketAddress src, InetSocketAddress dst) {
        // move position to the beginning of IP header
        buf.position(0);

        buf.put((byte) (IP4_VERSION << 4 | (byte) (headerLen/4)));  // IP version + IP header length
        buf.put((byte) 0);    // Type of service
        buf.putShort((short) ((short) headerLen + dataLen));  // IP datagram length
        buf.putShort((short) 0);    // Packet ID
        buf.putShort((short) 0x4000);    // FIXME: random number. Control bits + fragment offset
        buf.put(IP_TTL);        // non-zero TTL
        buf.put(protocol);        // Protocol UDP ID
        buf.putShort((short) 0);     // Checksum
        for (byte b : src.getAddress().getAddress()) {
            buf.put(b);
        }
        for (byte b : dst.getAddress().getAddress()) {
            buf.put(b);
        }

        Log.d(TAG, "src = " + src + " dst=" + dst);

        Utils.updateIPChecksum(buf);
        Utils.hexdump(buf, 20);
    }

    public void processConnect(SelectionKey key) {
        mTCPHandler.processConnect(key);
    }
}
