package trikita.capture;

import android.util.Log;
import android.util.Pair;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.HashMap;
import java.util.Map;

public class UDPHandler {

    private static final String TAG = "UDPHandler";
    private final Selector mSelector;
    private final VPNCaptureService mVPNService;

    private Map<Pair<InetSocketAddress, InetSocketAddress>, DatagramChannel> mSockets = new HashMap<>();

    public UDPHandler(Selector selector, VPNCaptureService svc) {
        mSelector = selector;
        mVPNService = svc;
    }


    public void processPacket(InetAddress srcAddress, InetAddress dstAddress, ByteBuffer ip) throws IOException {
        int srcPort = (ip.getShort() & 0xffff);
        int dstPort = (ip.getShort() & 0xffff);
        int len = (ip.getShort() & 0xffff);
        ip.getShort();  // skip "Checksum"
        Log.d(TAG, "UDP: srcAddress="+srcAddress+" dstAddress="+dstAddress+" srcPort="+srcPort+" dstPort="+dstPort+
                "\nremaining="+ip.remaining()+" len="+len);

        Log.d(TAG, "Open datagram channel");
        try {
            Pair<InetSocketAddress, InetSocketAddress> key =
                    new Pair<>(new InetSocketAddress(dstAddress, dstPort),
                            new InetSocketAddress(srcAddress, srcPort));
            DatagramChannel socket = mSockets.get(key);
            if (socket == null) {
                socket = DatagramChannel.open();
                Log.d(TAG, "Connecting..");
                socket.connect(key.first);
                Log.d(TAG, "Set non-blocking datagram channel");
                socket.configureBlocking(false);
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

    public int processData(DatagramChannel channel, ByteBuffer writeBuffer, int srcPort, int dstPort) throws IOException {
        // leave bytes for UDP datagram header
        writeBuffer.position(writeBuffer.position() + 8);

        int cnt = channel.read(writeBuffer);
        if (cnt <= 0) throw new IOException();

        // move position to the beginning of UDP header
        writeBuffer.position(20);

        // write UDP header
        writeBuffer.putShort((short) srcPort);
        writeBuffer.putShort((short) dstPort);
        writeBuffer.putShort((short) (8+cnt));
        writeBuffer.putShort((short) 0);

        // move position to the beginning of IP header
        writeBuffer.position(0);

        return 8+cnt;
    }
}
