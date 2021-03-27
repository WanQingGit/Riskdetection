package qing.risk.detection.checker;

import java.io.File;

import static qing.risk.detection.CommandUtil.exec;
import static qing.risk.detection.Utils.getProperty;

public final class RootChecker extends BaseChecker {


    private CheckResult checkSUExist() {
        File file;
        for (String path : suPaths) {
            file = new File(path, "su");
            if (file.exists()) {
                return addCheckResult("suExist", false, path + "su");
            }
        }
        return addCheckResult("suExist", true, null,0.8);
    }

    private CheckResult checkRoSecureProp() {
        String roSecureObj = getProperty("ro.secure");
        if ("0".equals(roSecureObj)) {
            return addCheckResult("ro.secure", false, "eng/userdebug版本，自带root权限");
        }
        return addCheckResult("ro.secure", true, roSecureObj,0.3);
    }


    public CheckResult checkRoDebuggableProp() {
        String roSecureObj = getProperty("ro.debuggable");
        if ("1".equals(roSecureObj)) {
            return addCheckResult("ro.debuggable", false, "可能root或adb有root权限",0.3);
        }
        return addCheckResult("ro.debuggable", true, roSecureObj,0.3);
    }

    private  CheckResult checkMagiskBinary() {
        String[] pathsArray = suPaths;
        for (String path : pathsArray) {
            File f = new File(path, "magisk");
            boolean fileExists = f.exists();
            if (fileExists) {
                String completePath = path + "magisk";
                return addCheckResult("magisk", false, completePath);
            }
        }
        return addCheckResult("magisk", true, "not find magisk binary",0.4);
    }


    private static final String[] suPaths = {
            "/data/local/",
            "/data/local/bin/",
            "/data/local/xbin/",
            "/sbin/",
            "/su/bin/",
            "/system/bin/",
            "/system/bin/.ext/",
            "/system/bin/failsafe/",
            "/system/sd/xbin/",
            "/system/usr/we-need-root/",
            "/system/xbin/",
            "/cache/",
            "/data/",
            "/dev/"
    };


    private  CheckResult checkSuperuser() {
        File file = new File("/system/app/Superuser.apk");
        if (file.exists()) {
            return addCheckResult("Superuser", false, "/system/app/Superuser.apk");
        }
        return addCheckResult("Superuser", true, null,0.1);
    }

    // try executing commands
    private  CheckResult checkWhichSu() {
        String[] commands = {
                "which su",
                "/system/bin/which su",
                "/system/xbin/which su"
        };
        for (String command : commands) {
            String result = exec(command);
            if (result.length() > 2 && result.contains("su")) {
                return addCheckResult("which su", false, command+":"+result);
            }
        }
        return addCheckResult("which su", true, null,0.7);
    }


}