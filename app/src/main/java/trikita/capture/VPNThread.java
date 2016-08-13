package trikita.capture;

import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.IOException;
import java.nio.channels.Selector;

public class VPNThread extends Thread {
    private static final String TAG = "VPNThread";
    private final Selector mSelector;

    private ParcelFileDescriptor mVpnFileDescriptor;

    public VPNThread(ParcelFileDescriptor fd) throws IOException {
        mVpnFileDescriptor = fd;
        mSelector = Selector.open();
    }

    @Override
    public void run() {
        try {
            while (!Thread.interrupted()) {
                Thread.sleep(1009);
                Log.d(TAG, "Tick");
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
        } finally {
            try {
                mVpnFileDescriptor.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
