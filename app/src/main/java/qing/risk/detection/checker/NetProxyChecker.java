package qing.risk.detection.checker;

import android.os.Build;
import android.text.TextUtils;


public class NetProxyChecker extends BaseChecker {

    public CheckResult checkWifiProxy() {
        final boolean IS_ICS_OR_LATER = Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH;
        String proxyAddress;
        int proxyPort;
        if (IS_ICS_OR_LATER) {
            proxyAddress = System.getProperty("http.proxyHost");
            String portStr = System.getProperty("http.proxyPort");
            proxyPort = Integer.parseInt((portStr != null ? portStr : "-1"));
        } else {
            proxyAddress = android.net.Proxy.getHost(application);
            proxyPort = android.net.Proxy.getPort(application);
        }
        if ((!TextUtils.isEmpty(proxyAddress)) && (proxyPort != -1)) {
            return addCheckResult("WifiProxy", false, proxyAddress + ":" + proxyPort);
        } else {
            return addCheckResult("WifiProxy", true, "");
        }
    }
}
