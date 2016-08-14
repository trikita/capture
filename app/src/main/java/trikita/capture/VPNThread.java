package trikita.capture;

import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
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

    private final Selector mSelector;
    private final FileChannel mVpnIn;
    private final FileChannel mVpnOut;
    private final IPHandler mIPHandler;

    private ParcelFileDescriptor mVpnFileDescriptor;
    private List<ByteBuffer> mWriteQueue = new ArrayList<>();

    public VPNThread(ParcelFileDescriptor fd, VPNCaptureService svc) throws IOException {
        mVpnFileDescriptor = fd;
        mVpnIn = new FileInputStream(mVpnFileDescriptor.getFileDescriptor()).getChannel();
        mVpnOut = new FileOutputStream(mVpnFileDescriptor.getFileDescriptor()).getChannel();
        mSelector = Selector.open();
        mIPHandler = new IPHandler(mSelector, svc, this);
    }

    @Override
    public void run() {
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
