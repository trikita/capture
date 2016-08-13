package trikita.capture;

import android.icu.text.LocaleDisplayNames;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.FileChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
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
        mIPHandler = new IPHandler(mSelector, svc);
    }

    @Override
    public void run() {
        try {
            while (!Thread.interrupted()) {
                ByteBuffer readBuffer = ByteBuffer.allocate(64 *1000);
                int readyChannels = mSelector.select(10); // terminate after 10ms if no FD becomes active

                readBuffer.clear();
                int len = mVpnIn.read(readBuffer);
                if (len > 0) {
                    Log.d(TAG, "read data len="+len);
                    readBuffer.flip();
                    mIPHandler.processIP(readBuffer);
                }

                for (ByteBuffer b : mWriteQueue) {
                    len = mVpnOut.write(b);
                    Log.d(TAG, "write data len="+len);
                }
                mWriteQueue.clear();

                if (readyChannels > 0) {
                    Set<SelectionKey> keys = mSelector.selectedKeys();
                    Iterator<SelectionKey> iter = keys.iterator();
                    while (iter.hasNext()) {
                        SelectionKey key = iter.next();
                        if (key.isValid() && key.isReadable()) {
                            iter.remove();

                            if (key.channel() instanceof DatagramChannel) {
                                ByteBuffer writeBuffer = mIPHandler.processUDPData(key);
                                if (writeBuffer != null) {
                                    mWriteQueue.add(writeBuffer);
                                }
                            }
                        }
                    }
                }
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
}
