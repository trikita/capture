package trikita.capture;

import android.content.Intent;
import android.net.VpnService;
import android.util.Log;

import java.io.IOException;

public class VPNCaptureService extends VpnService {
    private static final String TAG = "VPNCaptureService";
    public static final String START_VPN_ACTION = "trikita.capture.START_VPN";
    public static final String STOP_VPN_ACTION = "trikita.capture.STOP_VPN";

    private VPNThread mVpnThread;

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "onCreate");
    }

    @Override
    public void onDestroy() {
        Log.d(TAG, "onDestroy");
        super.onDestroy();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "onStartCommand");
        if (intent.getAction() == START_VPN_ACTION) {
            try {
                mVpnThread = new VPNThread(new Builder().addAddress("1.1.1.1", 32).establish());
            } catch (IOException e) {
                e.printStackTrace();
            }
            mVpnThread.start();
        } else if (intent.getAction() == STOP_VPN_ACTION) {
            mVpnThread.interrupt();
        }
        return START_STICKY;
    }
}
