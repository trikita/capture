package trikita.capture;

import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

public class VPNThread extends Thread {
    private static final String TAG = "VPNThread";

    private final FileChannel mVpnIn;
    private final FileChannel mVpnOut;
    private final SocketManager mSocketManager;
    private final VpnService mVPNService;
    private ParcelFileDescriptor mVpnFileDescriptor;

    public VPNThread(ParcelFileDescriptor fd, VPNCaptureService svc) throws IOException {
        mVpnFileDescriptor = fd;
        mVpnIn = new FileInputStream(mVpnFileDescriptor.getFileDescriptor()).getChannel();
        mVpnOut = new FileOutputStream(mVpnFileDescriptor.getFileDescriptor()).getChannel();
        mSocketManager = new SocketManager(this);
        mVPNService = svc;
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
            mVpnOut.write(ip);
            if (ip.hasRemaining()) {
                IPUtils.panic("incomplete write to VPN fd");
            }
        } catch (IOException e) {
            IPUtils.panic("exception in write to VPN fd" + e.getMessage());
        }
    }
}
