package qing.risk.detection.checker;

import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.LocalServerSocket;
import android.text.TextUtils;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.BindException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Random;

import static qing.risk.detection.CommandUtil.exec;

public class VirtualApkChecker extends BaseChecker {


    public interface VirtualCheckCallback {
        void findSuspect();
    }

    private String TAG = "test";


    /**
     * 维护一份市面多开应用的包名列表
     */
    private String[] virtualPkgs = {
            "com.droi.adocker.pro",//分身有术pro
            "com.lylm.dkzs",//多开助手
            "com.bly.dkplat",//多开分身
//            "dkplugin.pke.nnp",//多开分身克隆应用的包名会随机变换
            "com.by.chaos",//chaos引擎
            "com.lbe.parallel",//平行空间
            "com.excelliance.dualaid",//双开助手 多开分身
            "com.lody.virtual",//VirtualXposed，VirtualApp
            "com.qihoo.magic",//360分身大师
            "io.va.exposed",//VirtualXposed
//            "me.weishu.exp",//太极
            "io.virtualapp.sandvxposed", //SnadVXposed
    };

    /**
     * 通过检测app私有目录，多开后的应用路径会包含多开软件的包名
     *
     * @return
     */
    public CheckResult checkByPrivateFilePath() {
        String path = application.getFilesDir().getPath();
        for (String virtualPkg : virtualPkgs) {
            if (path.contains(virtualPkg)) {
                return addCheckResult("PrivateFilePath", false, path + " : " + virtualPkg);
            }
        }
        return addCheckResult("PrivateFilePath", true, path,0.5);
    }

    /**
     * 检测原始的包名，多开应用会hook处理getPackageName方法
     * 顺着这个思路，如果在应用列表里出现了同样的包，那么认为该应用被多开了
     */
    public CheckResult checkByOriginApkPackageName() {
        int count = 0;
        try {
            String packageName = application.getPackageName();
            PackageManager pm = application.getPackageManager();
            List<PackageInfo> pkgs = pm.getInstalledPackages(0);
            for (PackageInfo info : pkgs) {
                if (packageName.equals(info.packageName)) {
                    count++;
                }
            }
        } catch (Exception ignore) {
        }
        if (count > 1)
            return addCheckResult("MultiApkPackageName", false, "count=" + count);
        return addCheckResult("MultiApkPackageName", true, "count=" + count,0.7);

    }

    /**
     * 运行被克隆的应用，该应用会加载多开应用的so库
     * 检测已经加载的so里是否包含这些应用的包名
     *
     * @return
     */
    public boolean checkByMultiApkPackageName() {
        BufferedReader bufr = null;
        try {
            bufr = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = bufr.readLine()) != null) {
                for (String pkg : virtualPkgs) {
                    if (line.contains(pkg)) {
                        addCheckResult("Maps", false, pkg);
                        return true;
                    }
                }
            }
        } catch (Exception ignore) {
        } finally {
            if (bufr != null) {
                try {
                    bufr.close();
                } catch (IOException e) {

                }
            }
        }
        addCheckResult("Maps", true, null,0.8);
        return false;
    }

    /**
     * Android系统一个app一个uid
     * 如果同一uid下有两个进程对应的包名，在"/data/data"下有两个私有目录，则该应用被多开了
     */
    public CheckResult checkHasSameUid() {
        String filter = getUidStrFormat();
        if (TextUtils.isEmpty(filter)) return null;

        String result = exec("ps");
        if (TextUtils.isEmpty(result)) return null;

        String[] lines = result.split("\n");
        if (lines == null || lines.length <= 0) return null;

        int exitDirCount = 0;

        for (int i = 0; i < lines.length; i++) {
            if (lines[i].contains(filter)) {
                int pkgStartIndex = lines[i].lastIndexOf(" ");
                String processName = lines[i].substring(pkgStartIndex <= 0
                        ? 0 : pkgStartIndex + 1);
                File dataFile = new File(String.format("/data/data/%s", processName, Locale.CHINA));
                if (dataFile.exists()) {
                    exitDirCount++;
                }
            }
        }
        if (exitDirCount > 1) {
            return addCheckResult("SameUid", false, "count=" + exitDirCount);
        }
        return addCheckResult("SameUid", true, "count=" + exitDirCount,0.05);
    }

    private String getUidStrFormat() {
        String filter = exec("cat /proc/self/cgroup");
        if (filter == null || filter.length() == 0) {
            return null;
        }
        int uidStartIndex = filter.lastIndexOf("uid");
        int uidEndIndex = filter.lastIndexOf("/pid");
        if (uidStartIndex < 0) {
            return null;
        }
        if (uidEndIndex <= 0) {
            uidEndIndex = filter.length();
        }
        filter = filter.substring(uidStartIndex + 4, uidEndIndex);
        try {
            String strUid = filter.replaceAll("\n", "");
            if (isNumber(strUid)) {
                int uid = Integer.valueOf(strUid);
                filter = String.format("u0_a%d", uid - 10000);
                return filter;
            }
            return null;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private boolean isNumber(String str) {
        if (str == null || str.length() == 0) {
            return false;
        }
        for (int i = 0; i < str.length(); i++) {
            if (!Character.isDigit(str.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * 端口监听，先扫一遍已开启的端口并连接，
     * 如果发现能通信且通信信息一致，
     * 则认为之前有一个相同的自己打开了（也就是被多开了）
     * 如果没有，则开启监听
     * 这个方法没有 checkByCreateLocalServerSocket 方法简单，不推荐使用
     *
     */
    @Deprecated
    public void _checkByPortListening(String secret, VirtualCheckCallback callback) {
        startClient(secret);
        new ServerThread(secret, callback).start();
    }

    //此时app作为secret的接收方，也就是server角色
    private class ServerThread extends Thread {
        String secret;
        VirtualCheckCallback callback;

        private ServerThread(String secret, VirtualCheckCallback callback) {
            this.secret = secret;
            this.callback = callback;
        }

        @Override
        public void run() {
            super.run();
            startServer(secret, callback);
        }
    }

    //找一个没被占用的端口开启监听
    //如果监听到有连接，开启读线程
    private void startServer(String secret, VirtualCheckCallback callback) {
        Random random = new Random();
        ServerSocket serverSocket = null;
        try {
            serverSocket = new ServerSocket();
            serverSocket.bind(new InetSocketAddress("127.0.0.1",
                    random.nextInt(55534) + 10000));
            while (true) {
                Socket socket = serverSocket.accept();
                ReadThread readThread = new ReadThread(secret, socket, callback);
                readThread.start();
//                serverSocket.close();
            }
        } catch (BindException e) {
            startServer(secret, callback);//may be loop forever
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //读线程读流信息，如果包含secret则认为被广义多开
    private class ReadThread extends Thread {
        private ReadThread(String secret, Socket socket, VirtualCheckCallback callback) {
            InputStream inputStream = null;
            try {
                inputStream = socket.getInputStream();
                byte buffer[] = new byte[1024 * 4];
                int temp = 0;
                while ((temp = inputStream.read(buffer)) != -1) {
                    String result = new String(buffer, 0, temp);
                    if (result.contains(secret) && callback != null)
                        callback.findSuspect();
                }
                inputStream.close();
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    //读文件扫描已开启的端口，放入端口列表，每个端口都尝试连接一次
    private void startClient(String secret) {
        String tcp6 = exec("cat /proc/net/tcp6");
        if (TextUtils.isEmpty(tcp6)) return;
        String[] lines = tcp6.split("\n");
        ArrayList<Integer> portList = new ArrayList<>();
        for (int i = 0, len = lines.length; i < len; i++) {
            int localHost = lines[i].indexOf("0100007F:");//127.0.0.1:
            if (localHost < 0) continue;
            String singlePort = lines[i].substring(localHost + 9, localHost + 13);
            Integer port = Integer.parseInt(singlePort, 16);
            portList.add(port);
        }
        if (portList.isEmpty()) return;
        for (int port : portList) {
            new ClientThread(secret, port).start();
        }
    }

    //app此时作为secret的发送方（也就是client角色），发送完毕就结束
    private class ClientThread extends Thread {
        String secret;
        int port;

        private ClientThread(String secret, int port) {
            this.secret = secret;
            this.port = port;
        }

        @Override
        public void run() {
            super.run();
            try {
                Socket socket = new Socket("127.0.0.1", port);
                socket.setSoTimeout(2000);
                OutputStream outputStream = socket.getOutputStream();
                outputStream.write((secret + "\n").getBytes("utf-8"));
                outputStream.flush();
                socket.shutdownOutput();

                InputStream inputStream = socket.getInputStream();
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                String info = null;
                while ((info = bufferedReader.readLine()) != null) {
                    Log.i(TAG, "ClientThread: " + info);
                }

                bufferedReader.close();
                inputStream.close();
                socket.close();
            } catch (ConnectException e) {
                Log.i(TAG, port + "port refused");
            } catch (SocketException e) {
                e.printStackTrace();
            } catch (UnknownHostException e) {
                e.printStackTrace();
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * https://github.com/lamster2018/EasyProtector/issues/25
     *
     */
    private volatile LocalServerSocket localServerSocket;

    public final String UNIQUE_STR = "hll.checkc";

    public boolean checkByCreateLocalServerSocket() {
        if (localServerSocket != null) return false;
        try {
            localServerSocket = new LocalServerSocket(UNIQUE_STR);
            addCheckResult("CreateLocalServerSocket", true, null,0.9);
            return false;
        } catch (IOException e) {
            addCheckResult("CreateLocalServerSocket", false, null);
            return true;
        }
    }

    /**
     * TopActivity的检查顶层task的思路
     * https://github.com/109021017/android-TopActivity
     * TopActivity作为另一个进程（观察者的角度）
     * <p>
     * 能够正确识别多开软件的正确包名，类名
     * 这也是为什么能知道使用多开分身app多开后的应用包名是随机的。
     * 这里我只是提供调用方法，随时可能删掉。
     */
    public CheckResult checkByTopTask() {
        ActivityManager am = (ActivityManager) application.getSystemService(Context.ACTIVITY_SERVICE);
        List<ActivityManager.RunningTaskInfo> rtis = am.getRunningTasks(1);
        ComponentName topActivity = null;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
            topActivity = rtis.get(0).topActivity;
        } else {
            return null;
        }
        String packageName = topActivity.getPackageName();
        if (!packageName.equals(application.getPackageName())) {
            return addCheckResult("TopTask", false, packageName + "/" + topActivity.getClassName());
        }
        return addCheckResult("TopTask", true, packageName + "/" + topActivity.getClassName(),0.3);
    }
}
