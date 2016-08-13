package trikita.capture;

import android.content.Intent;
import android.net.VpnService;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";
    private static final int VPN_REQUEST_CODE = 1000;

    private Button mToggleVPNButton;
    private boolean isVPNStarted = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mToggleVPNButton = (Button) findViewById(R.id.btn_toggle_vpn);
    }

    public void onToggleCaptureClick(View v) {
        if (!isVPNStarted) {
            requestVPN();
        } else {
            stopVPN();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            startVPN();
        }
    }

    private void requestVPN() {
        Intent vpnIntent = VpnService.prepare(this);
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, VPN_REQUEST_CODE);
        } else {
            startVPN();
        }
    }

    private void startVPN() {
        isVPNStarted = true;
        startService(new Intent(this, VPNCaptureService.class).setAction(VPNCaptureService.START_VPN_ACTION));
        mToggleVPNButton.setText("Stop capture");
    }

    private void stopVPN() {
        isVPNStarted = false;
        startService(new Intent(this, VPNCaptureService.class).setAction(VPNCaptureService.STOP_VPN_ACTION));
        mToggleVPNButton.setText("Start capture");
    }
}
