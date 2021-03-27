package qing.risk.detection.checker;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Debug;
import android.text.TextUtils;

import java.io.BufferedReader;
import java.io.FileReader;
import java.lang.reflect.Field;

import static qing.risk.detection.Utils.getProperty;
import static qing.risk.detection.Utils.isMainThread;
import static qing.risk.detection.Utils.isPortUsing;

public class DebugChecker extends BaseChecker {
    private static final int CHECK_DEFAULT_PORT = 27042;

    /**
     * 判断是否是debug模式
     */
    public static boolean isBuildConfigDebug(Context context) {
        try {
            Class<?> clazz = Class.forName(context.getPackageName() + ".BuildConfig");
            Field field = clazz.getField("DEBUG");
            field.setAccessible(true);
            return field.getBoolean(null);
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            e.printStackTrace();
        }
        return false;
    }

    public CheckResult checkBuildConfig() {
        if (isBuildConfigDebug(application)) {
            return addCheckResult("BuildConfig.DEBUG", false, null);
        }
        return addCheckResult("BuildConfig.DEBUG", true, null);
    }

    public boolean checkDebuggable() {
        boolean b = 0 != (application.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE);
        if (b) {
            addCheckResult("FLAG_DEBUGGABLE", false, null);
        } else {
            addCheckResult("FLAG_DEBUGGABLE", true, null);
        }
        return b;
    }

    /**
     * pid调试检测
     */
    public CheckResult checkUnderTraced() {
        try {
            BufferedReader localBufferedReader = new BufferedReader(new FileReader("/proc/" + android.os.Process.myPid() + "/status"));
            int tracerPid = 0;
            for (; ; ) {
                String str = localBufferedReader.readLine();
                if (TextUtils.isEmpty(str) || !str.contains("TracerPid")) continue;
                String tracerPidStr = str.substring(str.indexOf(":") + 1).trim();
                if (TextUtils.isEmpty(tracerPidStr)) break;
                tracerPid = Integer.valueOf(tracerPidStr);
                break;
            }
            localBufferedReader.close();
            if (tracerPid > 100) {
                return addCheckResult("TracerPid", false, tracerPid + "");
            }
            return addCheckResult("TracerPid", true, tracerPid + "");
        } catch (Exception e) {
            e.printStackTrace();
            return new CheckResult("TracerPid", true, null);
        }
    }

    public CheckResult checkFrida() {
        final boolean[] portUsing=new boolean[1];
        if(isMainThread()){
            Thread thread = new Thread(new Runnable() {
                @Override
                public void run() {
                    portUsing[0] = isPortUsing("127.0.0.1", CHECK_DEFAULT_PORT);
                    synchronized (DebugChecker.this) {
                        DebugChecker.this.notify();
                    }
                }
            });
            synchronized (this) {
                try {
                    thread.start();
                    this.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }else{
            portUsing[0] = isPortUsing("127.0.0.1", CHECK_DEFAULT_PORT);
        }
        if (portUsing[0]) {
            return addCheckResult("FridaPort", false, null);
        }
        return addCheckResult("FridaPort", true, null,0.2);
    }
    public CheckResult checkRoDebuggableProp() {
        String roSecureObj = getProperty("ro.debuggable");
        if ("1".equals(roSecureObj)) {
            return addCheckResult("ro.debuggable", false, "可能被调试",0.5);
        }
        return addCheckResult("ro.debuggable", true, roSecureObj,0.3);
    }
    public CheckResult checkIsDebuggerConnected() {
        boolean isDebug = Debug.isDebuggerConnected();//被调试器连接了
        if (isDebug)
            return addCheckResult("isDebuggerConnected", false, null);
        return addCheckResult("isDebuggerConnected", true, null);
    }
}
