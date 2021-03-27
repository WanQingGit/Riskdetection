package qing.risk.detection;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import qing.risk.detection.R;

public class MainActivity extends Activity {

    public static final String TAG = "QING";

    static {
        System.loadLibrary("encrypt");
    }

    TextView tvPid;
    TextView tvDebuggable;
    TextView tvDebuggableFlag;
    TextView tvPackageCheck;
    TextView tvIdaPort;
    TextView tvSign;
    TextView tvTraceId;
    TextView tvAttachSelf;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        findViewById(R.id.btn).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                boolean res = isEquals("123456");
                Log.i(TAG, "res:" + res);
            }
        });
        tvPid = findViewById(R.id.pid);
        tvPid.setText("" + android.os.Process.myPid());
        tvDebuggable = findViewById(R.id.debuggable);
        tvDebuggableFlag = findViewById(R.id.debuggable_flag);
        tvPackageCheck = findViewById(R.id.is_own);
        tvIdaPort = findViewById(R.id.ida_port);
        tvSign = findViewById(R.id.sign);
        tvTraceId = findViewById(R.id.tid);
        tvAttachSelf = findViewById(R.id.attach_self);

        Button button = findViewById(R.id.checkAll);
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(qing.risk.detection.MainActivity.this, qing.risk.detection.CheckActivity.class));
            }
        });

    }

    public void refresh(View view) {
        tvDebuggable.setText(android.os.Debug.isDebuggerConnected() + "");
        if (0 != (getApplicationInfo().flags &= ApplicationInfo.FLAG_DEBUGGABLE)) {
            tvDebuggableFlag.setText("isDebuggable");
        } else {
            tvDebuggableFlag.setText("notDebuggable");
        }
        tvIdaPort.setText(Utils.isLoclePortUsing(23946) + " " + Utils.testFrida());
        tvTraceId.setText(getTraceId() + "");

    }

    public void traceSelf(View view) {
        long res = ptraceSelf();
        if (res < 0) {
            Toast.makeText(this, "attach self failed", Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(this, "attach self success", Toast.LENGTH_SHORT).show();
        }
        tvAttachSelf.setText("" + res);
    }

    private native long ptraceSelf();

    private static native int getTraceId();

    private native void traceCheck();

    private native boolean isEquals(String str);

}
