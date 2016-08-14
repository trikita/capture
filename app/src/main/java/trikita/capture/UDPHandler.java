package trikita.capture;

import android.util.Log;
import android.util.Pair;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.HashMap;
import java.util.Map;

public class UDPHandler {

    private static final String TAG = "UDPHandler";
    public static final byte UDP_HEADER_LEN = 8;    // 8 bytes

    private final Selector mSelector;
    private final VPNCaptureService mVPNService;

    private Map<Pair<InetSocketAddress, InetSocketAddress>, DatagramChannel> mSockets = new HashMap<>();

    public UDPHandler(Selector selector, VPNCaptureService svc) {
        mSelector = selector;
        mVPNService = svc;
    }

    // Unwraps raw data from a valid outgoing UDP datagram and sends to the net
    public void processInput(InetAddress srcAddress, InetAddress dstAddress, ByteBuffer ip) throws IOException {
        int srcPort = (ip.getShort() & 0xffff);
        int dstPort = (ip.getShort() & 0xffff);
        int len = (ip.getShort() & 0xffff);
        ip.getShort();  // skip "Checksum"
        Log.d(TAG, "UDP: srcAddress="+srcAddress+" dstAddress="+dstAddress+" srcPort="+srcPort+" dstPort="+dstPort+
                "\nremaining="+ip.remaining()+" len="+len);

        try {
            Pair<InetSocketAddress, InetSocketAddress> key =
                    new Pair<>(new InetSocketAddress(dstAddress, dstPort),
                            new InetSocketAddress(srcAddress, srcPort));
            DatagramChannel socket = mSockets.get(key);
            if (socket == null) {
                Log.d(TAG, "Open datagram channel");
                socket = DatagramChannel.open();
                Log.d(TAG, "Connecting..");
                socket.connect(key.first);
                Log.d(TAG, "Set non-blocking datagram channel");
                socket.configureBlocking(false);
                Log.d(TAG, "Register in selector for read");
                socket.register(mSelector, SelectionKey.OP_READ, key);
                Log.d(TAG, "Protect datagram channel socket from VPN");
                mVPNService.protect(socket.socket());
                mSockets.put(key, socket);
            }
            Log.d(TAG, "Write to datagram channel");
            int cnt = socket.write(ip);
            Log.d(TAG, "Done writing to datagram channel: cnt="+cnt);
        } catch (BufferUnderflowException e) {  // drop UDP datagram if body len != buffer.remaining()
            Log.d(TAG, "BufferUnderflowException:");
            e.printStackTrace();
        } catch (IndexOutOfBoundsException e) {  // drop UDP datagram if body len != buffer.remaining()
            Log.d(TAG, "IndexOutOfBoundsException:");
            e.printStackTrace();
        } catch (IOException e) {
            Log.d(TAG, "IOException:");
            e.printStackTrace();
        }
    }

    // Wraps raw data from the net into a valid incoming UDP datagram
    public byte processOutput(DatagramChannel channel, ByteBuffer writeBuffer, int srcPort, int dstPort) throws IOException {
        // leave bytes for UDP datagram header
        writeBuffer.position(writeBuffer.position() + UDP_HEADER_LEN);

        int cnt = channel.read(writeBuffer);
        if (cnt <= 0) throw new IOException();

        fillHeader(writeBuffer, srcPort, dstPort, UDP_HEADER_LEN+cnt);

        return (byte) (UDP_HEADER_LEN+cnt);
    }

    public static void fillHeader(ByteBuffer buf, int srcPort, int dstPort, int dataLen) {
        // move position to the beginning of UDP header
        buf.position(IPHandler.IP_HEADER_LEN);

        buf.putShort((short) srcPort);
        buf.putShort((short) dstPort);
        buf.putShort((short) dataLen);
        buf.putShort((short) 0);    // Checksum
    }
}
