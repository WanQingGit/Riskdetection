package qing.risk.detection;

import android.app.Application;
import android.content.Context;

public class MyApplication extends Application {

    private static Context mContext;
    private static Application mApplication;

    @Override
    public void onCreate() {
        super.onCreate();
        mContext = this.getApplicationContext();
        mApplication=this;

//        boolean isOwnApp = Utils.isOwnApp();
//        Log.i("jw", "isownapp:"+isOwnApp);
//        if(!isOwnApp){
//            Log.i("jw", "is not own app...exit app");
//            android.os.Process.killProcess(android.os.Process.myPid());
//        }

//        boolean isDebug = android.os.Debug.isDebuggerConnected();
//        Log.i("jw", "isDebug:" + isDebug);
//
//        if (0 != (getApplicationInfo().flags &= ApplicationInfo.FLAG_DEBUGGABLE)) {
//            Log.i("jw", "app isDebuggable");
//        }
//
//        boolean isPort = Utils.isLoclePortUsing(23946);
//        Log.i("jw", "port isused:" + isPort);

    }

    public static Context getMyContext() {
        return mContext;
    }
    public static Application getMyApplication() {
        return mApplication;
    }

}
