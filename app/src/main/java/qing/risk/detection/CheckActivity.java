package qing.risk.detection;

import android.os.Bundle;

import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.snackbar.Snackbar;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import android.view.View;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

import qing.risk.detection.checker.BaseChecker;
import qing.risk.detection.checker.DebugChecker;
import qing.risk.detection.checker.EmulatorChecker;
import qing.risk.detection.checker.NetProxyChecker;
import qing.risk.detection.checker.RootChecker;
import qing.risk.detection.checker.VirtualApkChecker;
import qing.risk.detection.checker.XposedChecker;

public class CheckActivity extends AppCompatActivity {


    List<BaseChecker> checkers = new ArrayList<>();
    TextView content;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_check);
        Toolbar toolbar = findViewById(R.id.toolbar);
        content = findViewById(R.id.check_result_content);
        setSupportActionBar(toolbar);

        checkers.add(new DebugChecker());
        checkers.add(new EmulatorChecker());
        checkers.add(new RootChecker());
        checkers.add(new VirtualApkChecker());
        checkers.add(new NetProxyChecker());
        checkers.add(new XposedChecker());


        FloatingActionButton fab = findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
            }
        });
    }

    public void checkAll(View view) {
        StringBuilder builder = new StringBuilder();
        for (BaseChecker checker : checkers) {
            boolean b = checker.startCheck();
            builder.append("\n[" + checker.getClass().getSimpleName() + "]" + (b ? "通过\n" : "不通过\n"));
            checker.getCheckResultSummary(builder);
        }
        content.setText(builder.toString());
    }
}
