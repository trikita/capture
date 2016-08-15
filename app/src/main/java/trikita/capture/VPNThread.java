package trikita.capture;

import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.FileChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class VPNThread extends Thread {
    private static final String TAG = "VPNThread";

    private final FileChannel mVpnIn;
    private final FileChannel mVpnOut;
    private final SocketManager mSocketManager;
    private final VpnService mVPNService;
    private ParcelFileDescriptor mVpnFileDescriptor;

    private final Selector mSelector;
    private final IPHandler mIPHandler;
    private List<ByteBuffer> mWriteQueue = new ArrayList<>();

    public VPNThread(ParcelFileDescriptor fd, VPNCaptureService svc) throws IOException {
        mVpnFileDescriptor = fd;
        mVpnIn = new FileInputStream(mVpnFileDescriptor.getFileDescriptor()).getChannel();
        mVpnOut = new FileOutputStream(mVpnFileDescriptor.getFileDescriptor()).getChannel();
        mSocketManager = new SocketManager(this);
        mVPNService = svc;

        mSelector = Selector.open();
        mIPHandler = new IPHandler(mSelector, svc, this);
    }

    @Override
    public void run() {
        ByteBuffer ip = ByteBuffer.allocate(IPUtils.MAX_DATAGRAM_SIZE);
        try {
            while (!Thread.interrupted()) {
                ip.clear();
                int n = mVpnIn.read(ip);
                if (n > 0) {
                    ip.flip();
                    mSocketManager.processIPOut(ip);
                }
                mSocketManager.select(ip);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                mVpnFileDescriptor.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void protect(Socket channel) {
        mVPNService.protect(channel);
    }

    public void protect(DatagramSocket channel) {
        mVPNService.protect(channel);
    }

    public void write(ByteBuffer ip) {
        try {
            Log.d(TAG, IPUtils.hexdump("INCOMING IP PACKET:", ip));
            mVpnOut.write(ip);
            if (ip.hasRemaining()) {
                IPUtils.panic("incomplete write to VPN fd");
            }
        } catch (IOException e) {
            IPUtils.panic("exception in write to VPN fd" + e.getMessage());
        }
    }

    public void runX() {
        try {
            while (!Thread.interrupted()) {
                ByteBuffer readBuffer = ByteBuffer.allocate(IPHandler.IP_PACKET_SIZE);
                int readyChannels = mSelector.select(10); // terminate after 10ms if no FD becomes active

                readBuffer.clear();
                int len = mVpnIn.read(readBuffer);
                if (len > 0) {
                    Log.d(TAG, "read data len="+len);
                    readBuffer.flip();
                    mIPHandler.processInput(readBuffer);
                }

                if (readyChannels > 0) {
                    Set<SelectionKey> keys = mSelector.selectedKeys();
                    for (SelectionKey key : keys) {
                        if (key.isValid() && key.isReadable()) {
                            ByteBuffer writeBuffer = mIPHandler.processOutput(key);
                            if (writeBuffer != null) {
                                mWriteQueue.add(writeBuffer);
                            }
                        }
                        if (key.isValid() && key.isConnectable()) {
                            mIPHandler.processConnect(key);
                        }
                    }
                }

                for (ByteBuffer b : mWriteQueue) {
                    Log.d(TAG, "WRITING IP PACKET");
                    Utils.hexdump(b, b.remaining());
                    len = mVpnOut.write(b);
                    Log.d(TAG, "write IP data="+len);
                }
                mWriteQueue.clear();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                mSelector.close();
                mVpnFileDescriptor.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void addToOutput(ByteBuffer buffer) {
        mWriteQueue.add(buffer);
    }
}
