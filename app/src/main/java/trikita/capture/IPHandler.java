package trikita.capture;

import android.util.Log;
import android.util.Pair;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;

public class IPHandler {

    private static final String TAG = "IPHandler";

    private final Selector mSelector;
    private final UDPHandler mUDPHandler;

    public IPHandler(Selector selector, VPNCaptureService svc) {
        mSelector = selector;
        mUDPHandler = new UDPHandler(mSelector, svc);
    }

    public void processIP(ByteBuffer ip) throws IOException {
        //hexdump(ip, 64);
        byte header = ip.get();
        if ((header & 0xf0) != 0x40) {
            throw new IOException("not an IP packet header: " + header);
        }
        int headerLen = (header & 0x0f) * 4;
        ip.get(); // skip "Type of Service"
        int totalLength = ip.getShort() & 0xffff;
        ip.getInt();   // skipping till "Protocol"
        ip.get();   // skipping till "Protocol"
        int protocol = (ip.get() & 0xff);

        if (protocol != 6 && protocol != 17) {
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
        for (int i = 0; i < (headerLen - 20); i++) {
            ip.get();
        }
        if (protocol == 6) {    // TCP packet
            //Log.d(TAG, "TCP packet detected: protocol="+protocol);
        } else if (protocol == 17) {     // UDP packet
            Log.d(TAG, "UDP packet detected: protocol=" + protocol);
            mUDPHandler.processPacket(srcAddress, dstAddress, ip);
        }
    }

    private final static char[] HEX = "0123456789abcdef".toCharArray();

    private void hexdump(ByteBuffer b, int len) {
        int pos = b.position();
        StringBuilder sb = new StringBuilder();
        len = Math.min(len, b.remaining());
        for (int i = 0; i < len; i++) {
            byte octet = b.get();
            sb.append(HEX[((octet & 0xf0) >> 4)]);
            sb.append(HEX[(octet & 0x0f)]);
            sb.append(' ');
        }
        b.position(pos);
        Log.d(TAG, sb.toString());
    }

    public ByteBuffer processUDPData(SelectionKey key) {
        ByteBuffer writeBuffer = ByteBuffer.allocate(64 * 1024);
        // leave bytes for IP
        writeBuffer.position(20);

        Pair<InetSocketAddress, InetSocketAddress> attachment = (Pair<InetSocketAddress, InetSocketAddress>) key.attachment();
        InetSocketAddress src = attachment.first;
        InetSocketAddress dst = attachment.second;
        try {
            int numBytes = mUDPHandler.processData((DatagramChannel) key.channel(), writeBuffer, src.getPort(), dst.getPort());

            // write IP header
            writeBuffer.put((byte) 0x45);  // IP version + IP header length
            writeBuffer.put((byte) 0);    // Type of service
            writeBuffer.putShort((short) (20 + numBytes));  // IP datagram length
            writeBuffer.putShort((short) 0);    // Packet ID
            writeBuffer.putShort((short) 0x4000);    // Control bits + fragment offset
            writeBuffer.put((byte) 64);        // non-zero TTL
            writeBuffer.put((byte) 0x11);        // Protocol UDP ID
            writeBuffer.putShort((short) 0);     // Checksum
            for (byte b : src.getAddress().getAddress()) {
                writeBuffer.put(b);
            }
            for (byte b : dst.getAddress().getAddress()) {
                writeBuffer.put(b);
            }

            writeBuffer.position(0);
            updateChecksum(writeBuffer);
            writeBuffer.position(0);
            writeBuffer.limit(20+numBytes);

            hexdump(writeBuffer, 64);
            return writeBuffer;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private void updateChecksum(ByteBuffer buf) {
        int sum = 0;
        int headerLength = 20;
        while (headerLength> 0) {
            sum += BitUtils.getUnsignedShort(buf.getShort());
            headerLength -= 2;
        }
        while (sum >> 16 > 0)
            sum = (sum & 0xFFFF) + (sum >> 16);

        sum = ~sum;
        buf.putShort(10, (short) sum);
    }

    private static class BitUtils {
        private static short getUnsignedByte(byte value) { return (short)(value & 0xFF); }

        private static int getUnsignedShort(short value) { return value & 0xFFFF; }

        private static long getUnsignedInt(int value) { return value & 0xFFFFFFFFL; }
    }
}
