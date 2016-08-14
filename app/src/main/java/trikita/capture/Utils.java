package trikita.capture;

import android.util.Log;

import java.nio.ByteBuffer;

public class Utils {

    private static final String TAG = "Utils";
    private final static char[] HEX = "0123456789abcdef".toCharArray();

    public static void hexdump(ByteBuffer b, int len) {
        int pos = b.position();
        StringBuilder sb = new StringBuilder();
        len = Math.min(len, b.remaining());
        for (int i = 0; i < len; i++) {
            byte octet = b.get();
            sb.append(HEX[((octet & 0xf0) >> 4)]);
            sb.append(HEX[(octet & 0x0f)]);
            sb.append(' ');
            if (i % 16 == 15) {
                sb.append('\n');
            }
        }
        b.position(pos);
        Log.d(TAG, sb.toString());
    }

    public static void updateIPChecksum(ByteBuffer buf) {
        // move position to the beginning of IP header
        buf.position(0);

        int sum = 0;
        int headerLength = IPHandler.IP_HEADER_LEN;
        while (headerLength > 0) {
            sum += Utils.getUnsignedShort(buf.getShort());
            headerLength -= 2;
        }
        while (sum >> 16 > 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        sum = ~sum;
        buf.putShort(10, (short) sum);

        // restore previous position at the beginning of IP header
        buf.position(0);
    }

    public static void updateTCPChecksum(ByteBuffer buf, byte[] srcAddr, byte[] dstAddr, byte headerLength, int payloadSize) {
        int sum = 0;
        int tcpLength = headerLength + payloadSize;

        // Calculate pseudo-header checksum
        sum = (((srcAddr[0] & 0xff) << 8) | (srcAddr[1] & 0xff)) +
                (((srcAddr[2] & 0xff) << 8) | (srcAddr[3] & 0xff));
        sum += (((dstAddr[0] & 0xff) << 8) | (dstAddr[1] & 0xff)) +
                (((dstAddr[2] & 0xff) << 8) | (dstAddr[3] & 0xff));

        sum += IPHandler.TCP_PROTOCOL + tcpLength;

        // Calculate TCP segment checksum
        buf.position(IPHandler.IP_HEADER_LEN);
        while (tcpLength > 1) {
            int x = (buf.getShort() & 0xffff);
            sum += x;
            tcpLength -= 2;
        }
        if (tcpLength > 0) {
            sum += (buf.get() & 0xff) << 8;
        }

        while (sum >> 16 > 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        sum = ~sum;

        buf.putShort(IPHandler.IP_HEADER_LEN + 16, (short) sum);

        // restore previous position at the end of TCP header
        buf.position(IPHandler.IP_HEADER_LEN+headerLength);
    }

    public static short getUnsignedByte(byte value) { return (short)(value & 0xFF); }

    public static int getUnsignedShort(short value) { return value & 0xFFFF; }

    public static long getUnsignedInt(int value) { return value & 0xFFFFFFFFL; }
}
