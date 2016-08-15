package trikita.capture;

import android.util.Log;
import android.util.Pair;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Arrays;

public final class IPUtils {
    private static final String TAG = "IPUtils";

    public static final int MAX_DATAGRAM_SIZE = 0xffff;
    public static final int PROTO_TCP = 6;
    public static final int PROTO_UDP = 17;

    private final static char[] HEX = "0123456789abcdef".toCharArray();

    public static void panic(String s) {
        Log.d(TAG, "#############\n### PANIC ###\n#############\n" );
        try {
            throw new RuntimeException(s);
        } catch (RuntimeException e) {
            e.printStackTrace();
        }
    }

    public static String hexdump(String prefix, ByteBuffer b) {
        int pos = b.position();
        StringBuilder sb = new StringBuilder(prefix).append("\n  ");
        int len = b.remaining();
        for (int i = 0; i < len; i++) {
            byte octet = b.get();
            sb.append(HEX[((octet & 0xf0) >> 4)]);
            sb.append(HEX[(octet & 0x0f)]);
            sb.append(' ');
            if (i % 16 == 15) {
                sb.append("\n  ");
            }
        }
        b.position(pos);
        return sb.toString();
    }

    public static class SocketID extends Pair<InetSocketAddress, InetSocketAddress> {
        private SocketID(InetSocketAddress first, InetSocketAddress second) {
            super(first, second);
        }
        public static SocketID fromIP(IPHeader ip, int srcPort, int dstPort) {
            try {
                InetSocketAddress src = new InetSocketAddress(InetAddress.getByAddress(ip.src), srcPort);
                InetSocketAddress dst = new InetSocketAddress(InetAddress.getByAddress(ip.dst), dstPort);
                return new SocketID(src, dst);
            } catch (UnknownHostException e) {
                IPUtils.panic("host expected to be resolvable" + e.getMessage());
                return null;
            }
        }
        public static SocketID fromUDP(IPHeader ip, UDPHeader udp) {
            return fromIP(ip, udp.srcPort, udp.dstPort);
        }
        public static SocketID fromTCP(IPHeader ip, TCPHeader tcp) {
            return fromIP(ip, tcp.srcPort, tcp.dstPort);
        }
        public InetSocketAddress src() {
            return this.first;
        }
        public InetSocketAddress dst() {
            return this.second;
        }

        @Override
        public String toString() {
            return new StringBuilder().append("src=").append(this.first)
                    .append(", dst = ").append(this.second).toString();
        }
    }

    public static class IPHeader {

        public static final int DEFAULT_LENGTH = 20;
        public static final int IP4_VERSION = 4;
        private static final int DEFAULT_TTL = 100;
        private static final short CHECKSUM_OFFSET = 10;

        public int version;
        public int headerLength;
        public int typeOfService;
        public int length;
        public int id;
        public int flags;
        public int fragmentOffset;
        public int ttl;
        public int protocol;
        public int checksum;
        public byte[] src;
        public byte[] dst;

        public static IPHeader parse(ByteBuffer ip, IPHeader reuse) {
            IPHeader header = (reuse != null ? reuse : new IPHeader());
            int n = ip.get();
            header.version = (n >> 4) & 0xff;
            // TODO: ipv6 support
            if (header.version != 4) {
                IPUtils.panic("unexpected IP protocol version: " + header.version);
                return header;
            }
            header.headerLength = (n & 0x0f) * 4;
            header.typeOfService = (ip.get() & 0xff);
            header.length = (ip.getShort() & 0xffff);
            header.id = (ip.getShort() & 0xffff);
            int fragment = (ip.getShort() & 0xffff);
            header.flags = fragment >> 5;
            header.fragmentOffset = fragment & (0x1fff);
            header.ttl = (ip.get() & 0xff);
            header.protocol = (ip.get() & 0xff);
            header.checksum = (ip.getShort() & 0xffff);
            if (header.src == null || header.src.length != 4) {
                header.src = new byte[4];
            }
            if (header.dst == null || header.dst.length != 4) {
                header.dst = new byte[4];
            }
            header.src[0] = ip.get();
            header.src[1] = ip.get();
            header.src[2] = ip.get();
            header.src[3] = ip.get();

            header.dst[0] = ip.get();
            header.dst[1] = ip.get();
            header.dst[2] = ip.get();
            header.dst[3] = ip.get();

            ip.position(header.headerLength);

            return header;
        }

        public static void fill(ByteBuffer ip, InetSocketAddress src, InetSocketAddress dst, int proto, int n) {
            byte[] srcAddr = src.getAddress().getAddress();
            byte[] dstAddr = dst.getAddress().getAddress();

            ip.put((byte) (IP4_VERSION << 4 | (DEFAULT_LENGTH/4)));
            ip.put((byte) 0);            // Type of service
            ip.putShort((short) (DEFAULT_LENGTH + n));  // IP datagram length
            ip.putShort((short) 0);      // Packet ID
            ip.putShort((short) 0x4000); // FIXME: random number. Control bits + fragment offset
            ip.put((byte) DEFAULT_TTL);  // non-zero TTL
            ip.put((byte) proto);        // Protocol ID
            ip.putShort((short) 0);      // Checksum
            if (srcAddr.length == 4 && dstAddr.length == 4) {
                for (byte b : srcAddr) ip.put(b);
                for (byte b : dstAddr) ip.put(b);
            } else {
                IPUtils.panic("unexpected address length: " + srcAddr.length + " " + dstAddr.length);
            }
            updateChecksum(ip);
        }

        private static void updateChecksum(ByteBuffer ip) {
            int sum = 0;
            ip.position(0);
            for (int i = DEFAULT_LENGTH; i > 0; i -= 2) {
                sum += (ip.getShort() & 0xffff);
            }
            while ((sum >> 16) > 0) {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            sum = ~sum;
            ip.putShort(CHECKSUM_OFFSET, (short) sum);
        }

        @Override
        public String toString() {
            return new StringBuilder("IP{").append("version=").append(version)
                    .append(", headerLength=").append(headerLength)
                    .append(", typeOfService=").append(typeOfService)
                    .append(", length=").append(length)
                    .append(", id=").append(id)
                    .append(", flags=").append(flags)
                    .append(", fragmentOffset=").append(fragmentOffset)
                    .append(", ttl=").append(ttl)
                    .append(", protocol=").append(protocol)
                    .append(", checksum=").append(checksum)
                    .append(", src=").append(Arrays.toString(src))
                    .append(", dst=").append(Arrays.toString(dst))
                    .append('}').toString();
        }
    }

    public static class UDPHeader {
        public static final int DEFAULT_LENGTH = 8;
        public int srcPort;
        public int dstPort;
        public int length;
        public int checksum;

        public static UDPHeader parse(ByteBuffer udp, UDPHeader reuse) {
            UDPHeader header = (reuse != null ? reuse : new UDPHeader());
            header.srcPort = (udp.getShort() & 0xffff);
            header.dstPort = (udp.getShort() & 0xffff);
            header.length = (udp.getShort() & 0xffff);
            header.checksum = (udp.getShort() & 0xffff);
            return header;
        }

        public static void fill(ByteBuffer udp, InetSocketAddress src, InetSocketAddress dst, int n) {
            udp.putShort((short) src.getPort());
            udp.putShort((short) dst.getPort());
            udp.putShort((short) (DEFAULT_LENGTH + n));
            // Checksum can be zero according to the RFC
            udp.putShort((short) 0);
        }

        @Override
        public String toString() {
            return new StringBuilder().append("UDP{")
                    .append("srcPort=").append(srcPort)
                    .append(", dstPort=").append(dstPort)
                    .append(", length=").append(length)
                    .append(", checksum=").append(checksum)
                    .append('}').toString();
        }
    }

    public static class TCPHeader {
        public static final int DEFAULT_LENGTH = 20;
        public static final byte TCP_FLAG_FIN = (1 << 0);
        public static final byte TCP_FLAG_SYN = (1 << 1);
        public static final byte TCP_FLAG_RST = (1 << 2);
        public static final byte TCP_FLAG_PSH = (1 << 3);
        public static final byte TCP_FLAG_ACK = (1 << 4);
        public static final byte TCP_FLAG_URG = (1 << 5);

        public int srcPort;
        public int dstPort;
        public int seq;
        public int ack;
        public int dataOffset;
        public int flags;
        public int window;
        public int checksum;
        public int urgent;


        public static TCPHeader parse(ByteBuffer tcp, TCPHeader reuse) {
            TCPHeader header = (reuse != null ? reuse : new TCPHeader());
            int position = tcp.position();
            header.srcPort = (tcp.getShort() & 0xffff);
            header.dstPort = (tcp.getShort() & 0xffff);
            header.seq = tcp.getInt();
            header.ack = tcp.getInt();
            int n = tcp.getShort();
            header.dataOffset = ((n & 0xffff) >> 12) * 4;
            header.flags = (n & 0x3f);
            header.window = (tcp.getShort() & 0xffff);
            header.checksum = (tcp.getShort() & 0xffff);
            header.urgent = (tcp.getShort() & 0xffff);

            tcp.position(position + header.dataOffset);

            return header;
        }

        public static void fill(ByteBuffer tcp, InetSocketAddress src, InetSocketAddress dst, int seq, int ack, int flags, int n) {
            int position = tcp.position();
            tcp.putShort((short) src.getPort());
            tcp.putShort((short) dst.getPort());
            tcp.putInt(seq);
            tcp.putInt(ack);
            tcp.put((byte) ((DEFAULT_LENGTH/4) << 4));
            tcp.put((byte) flags);
            tcp.putShort((short) 0xffff); // TODO: window size
            tcp.putShort((short) 0); // Clear checksum
            tcp.putShort((short) 0); // No urgent pointer
            tcp.position(position);
            updateChecksum(tcp, src, dst, n);
        }

        private static void updateChecksum(ByteBuffer tcp, InetSocketAddress src, InetSocketAddress dst, int n) {
            int sum = 0;
            int pos = tcp.position();
            byte[] srcAddr = src.getAddress().getAddress();
            byte[] dstAddr = dst.getAddress().getAddress();

            // Calculate pseudo-header checksum
            sum = (((srcAddr[0] & 0xff) << 8) | (srcAddr[1] & 0xff)) +
                    (((srcAddr[2] & 0xff) << 8) | (srcAddr[3] & 0xff)) +
                    (((dstAddr[0] & 0xff) << 8) | (dstAddr[1] & 0xff)) +
                    (((dstAddr[2] & 0xff) << 8) | (dstAddr[3] & 0xff)) +
                    PROTO_TCP + DEFAULT_LENGTH + n;

            // Calculate TCP segment checksum
            for (int i = DEFAULT_LENGTH + n; i > 1; i -= 2) {
                int x = (tcp.getShort() & 0xffff);
                sum += x;
            }
            if (n % 2 > 0) {
                sum += (tcp.get() & 0xff) << 8;
            }
            while ((sum >> 16) > 0) {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            sum = ~sum;
            tcp.putShort(pos + 16, (short) sum);
        }

        @Override
        public String toString() {
            return new StringBuilder().append("TCP{")
                    .append("srcPort=").append(srcPort)
                    .append(", dstPort=").append(dstPort)
                    .append(", seq=").append(seq)
                    .append(", ack=").append(ack)
                    .append(", dataOffset=").append(dataOffset)
                    .append(", flags=").append(flags)
                    .append(", window=").append(window)
                    .append(", checksum=").append(checksum)
                    .append(", urgent=").append(urgent)
                    .append('}').toString();
        }
    }
}
