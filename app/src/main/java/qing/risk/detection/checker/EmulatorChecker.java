package qing.risk.detection.checker;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.net.Uri;
import android.os.Build;
import android.telephony.TelephonyManager;
import android.text.TextUtils;

import static android.content.Context.SENSOR_SERVICE;
import static qing.risk.detection.CommandUtil.exec;
import static qing.risk.detection.Utils.getProperty;

public class EmulatorChecker extends BaseChecker {


//    /**
//     * 通过Prop 判断是否在模拟器中
//     * @return true 在模拟器中运行
//     */
//    private fun detectEmulatorByProp(propMap: HashMap<String, String>) {
//        val matchKv = { key: String, value: String? ->
//        when (key) {
//            "ro.kernel.qemu" -> {
//                // 模拟器中为1，通常在正常手机中没有该属性
//                "1" == value
//            }
//            "ro.build.tags" -> {
//                // 部分模拟器中为test-keys，通常在正常手机中它的值为release-keys
//                "release-keys" != value
//            }
//            }
//        }
//        }
//    }


    public CheckResult checkDial() {
        String url = "tel:" + "123456";
        Intent intent = new Intent();
        intent.setData(Uri.parse(url));
        intent.setAction(Intent.ACTION_DIAL);
        boolean checkDial = intent.resolveActivity(application.getPackageManager()) == null;
        if (checkDial) return addCheckResult("dial", false, "无法拨打电话");
        return addCheckResult("dial", true, "含有拨打电话功能", 0.2);
    }

    public CheckResult checkTelephony() {
        String operatorName = "";
        TelephonyManager tm = (TelephonyManager) application.getSystemService(Context.TELEPHONY_SERVICE);
        if (tm != null) {
            String name = tm.getNetworkOperatorName();
            if (name != null) {
                operatorName = name;
            }
        }
        if (operatorName.toLowerCase().equals("android")) {
            return addCheckResult("Telephony", false, null);
        }
        return addCheckResult("Telephony", true, null, 0.2);
    }

    public CheckResult checkOther() {
        String fingerprint = Build.FINGERPRINT;
        boolean checkProperty = fingerprint.startsWith("generic")
                || fingerprint.toLowerCase().contains("vbox")
//                || fingerprint.toLowerCase().contains("test-keys")
                || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
                || "google_sdk".equals(Build.PRODUCT);
        if (checkProperty) {
            return addCheckResult("ohter", false, fingerprint + " " + Build.PRODUCT);
        }
        String tags = Build.TAGS;
        if (tags.contains("test-keys"))
            return addCheckResult("ro.build.tags", false, tags + " " + Build.BRAND + " " + Build.DEVICE + " " + Build.PRODUCT, 0.1);
        return addCheckResult("other", true, fingerprint + " " + " " + Build.PRODUCT, 0.2);
    }

    /**
     * 特征参数-硬件名称
     */
    private CheckResult checkHardware() {
        String hardware = getProperty("ro.hardware");
        if (null == hardware || hardware.length() < 2)
            return addCheckResult("ro.hardware", false, "硬件名称=" + hardware, 0.2);
        String tempValue = hardware.toLowerCase();
        switch (tempValue) {
            case "ttvm"://天天模拟器
            case "nox"://夜神模拟器
            case "cancro"://网易MUMU模拟器
            case "intel"://逍遥模拟器
            case "vbox":
            case "vbox86"://腾讯手游助手
            case "android_x86"://雷电模拟器
                return addCheckResult("ro.hardware", false, "硬件名称=" + hardware);
            default:
                return addCheckResult("ro.hardware", true, "硬件名称=" + hardware, 0);
        }
    }

    /**
     * 特征参数-架构
     * x86架构在真机中极少，后续若出现单独适配
     */
    private CheckResult checkAbi() {
        String abi = getProperty("ro.product.cpu.abi");
        if (null == abi || abi.length() < 2)
            return addCheckResult("ro.product.cpu.abi", false, "架构=" + abi, 0.1);
        String tempValue = abi.toLowerCase();
        if (tempValue.contains("x86"))
            return addCheckResult("ro.product.cpu.abi", false, "架构=" + abi, 0.4);
        return addCheckResult("ro.product.cpu.abi", true, "架构=" + abi, 0);
    }

    /**
     * 特征参数-渠道
     */
    private CheckResult checkFlavor() {
        String flavor = getProperty("ro.build.flavor");
        if (null == flavor || flavor.length() < 2)
            return addCheckResult("ro.build.flavor", false, "渠道" + flavor, 0.1);
        String tempValue = flavor.toLowerCase();
        if (tempValue.contains("vbox") || tempValue.contains("sdk_gphone"))
            return addCheckResult("ro.build.flavor", false, "渠道" + flavor);
        return addCheckResult("ro.build.flavor", true, "渠道" + flavor, 0);
    }

    /**
     * 特征参数-设备型号
     */
    private CheckResult checkModel() {
        String model = getProperty("ro.product.model");
        if (null == model || model.length() < 2)
            return addCheckResult("ro.product.model", false, "设备型号=" + model, 0.3);
        String tempValue = model.toLowerCase();
        // it.contains("Android SDK") || (it == "sdk")
        if (tempValue.contains("android sdk") || tempValue.equals("sdk") || tempValue.contains("google_sdk") || tempValue.contains("emulator") || tempValue.contains("android sdk built for x86"))
            return addCheckResult("ro.product.model", false, "设备型号=" + model);
        return addCheckResult("ro.product.model", true, "设备型号=" + model, 0);
    }

    /**
     * 特征参数-硬件制造商
     */
    private CheckResult checkManufacturer() {
        String manufacturer = getProperty("ro.product.manufacturer");
        if (null == manufacturer || manufacturer.length() < 2)
            return addCheckResult("ro.product.manufacturer", false, "硬件制造商=" + manufacturer, 0.3);
        int result;
        String tempValue = manufacturer.toLowerCase();
        if (tempValue.contains("genymotion") || tempValue.contains("netease"))
            return addCheckResult("ro.product.manufacturer", false, "硬件制造商=" + manufacturer);
        return addCheckResult("ro.product.manufacturer", true, "硬件制造商" + manufacturer, 0.1);
    }

    /**
     * 特征参数-主板名称
     */
    private CheckResult checkBoard() {
        String board = getProperty("ro.product.board");
        if (null == board || board.length() < 2)
            return addCheckResult("ro.product.board", false, "主板名称=" + board);
        String tempValue = board.toLowerCase();
        if (tempValue.contains("android") || tempValue.contains("goldfish"))
            return addCheckResult("ro.product.board", false, "主板名称=" + board);
        return addCheckResult("ro.product.board", true, "主板名称=" + board, 0.2);
    }

    /**
     * 特征参数-主板平台
     */
    private CheckResult checkPlatform() {
        String platform = getProperty("ro.board.platform");
        if (null == platform || platform.length() < 2)
            return addCheckResult("ro.board.platform", false, "主板平台=" + platform, 0.3);
        String tempValue = platform.toLowerCase();
        if (tempValue.contains("android"))
            return addCheckResult("ro.board.platform", false, platform);
        return addCheckResult("ro.board.platform", true, platform, 0.2);
    }

    /**
     * 特征参数-基带信息
     */
    private CheckResult checkBaseBand() {
        String baseBandVersion = getProperty("gsm.version.baseband");
        if (null == baseBandVersion)
            return addCheckResult("gsm.version.baseband", false, "基带信息", 0.4);
        if (baseBandVersion.contains("1.0.0.0"))
            return addCheckResult("gsm.version.baseband", false, "基带信息", 0.1);
        return addCheckResult("gsm.version.baseband", true, "基带信息", 0.2);
    }

    /**
     * 获取传感器数量
     */
    private CheckResult checkSensorNumber() {
        SensorManager sm = (SensorManager) application.getSystemService(SENSOR_SERVICE);
        int sensorNumber = sm.getSensorList(Sensor.TYPE_ALL).size();
        if (sensorNumber <= 7) {
            double weight = 1.0;
            if (sensorNumber > 4)
                weight = 1 - sensorNumber / 8;
            CheckResult result = addCheckResult("SensorNumber", false, "传感器数量=" + sensorNumber, weight);
            return result;
        }
        return addCheckResult("SensorNumber", true, "传感器数量=" + sensorNumber, Math.min(sensorNumber / 20.0, 0.8));
    }

    /**
     * 获取已安装第三方应用数量
     */
    private CheckResult checkUserAppNumber() {
        String userApps = exec("pm list package -3");
        if (TextUtils.isEmpty(userApps))
            return addCheckResult("UserAppNumber", false, "已安装第三方应用数量=0", 0.01);
        String[] result = userApps.split("package:");
        if (result.length <= 5)
            return addCheckResult("UserAppNumber", false, "已安装第三方应用数量=" + result.length, 0.01);
        return addCheckResult("UserAppNumber", true, "已安装第三方应用数量=" + result.length, Math.min(result.length / 32, 0.6));
    }

    /**
     * 是否支持相机
     */
    private boolean checkSupportCamera() {
        boolean b = application.getPackageManager().hasSystemFeature(PackageManager.FEATURE_CAMERA);
        if (b) {
            addCheckResult("SupportCamera", true, "支持相机", 0.2);
        } else {
            addCheckResult("SupportCamera", true, "不支持相机", 0.4);
        }
        return b;
    }

    /**
     * 是否支持闪光灯
     */
    private boolean checkSupportCameraFlash() {
        boolean b = application.getPackageManager().hasSystemFeature(PackageManager.FEATURE_CAMERA_FLASH);
        if (b) {
            addCheckResult("SupportCameraFlash", true, "支持闪光灯");
        } else {
            addCheckResult("SupportCameraFlash", false, "不支持闪光灯", 0.2);
        }
        return b;
    }

    /**
     * 是否支持蓝牙
     */
    private boolean checkSupportBluetooth() {
        boolean support = application.getPackageManager().hasSystemFeature(PackageManager.FEATURE_BLUETOOTH);
        if (support)
            addCheckResult("SupportBluetooth", true, "支持蓝牙");
        else
            addCheckResult("SupportBluetooth", false, "不支持蓝牙", 0.5);
        return support;
    }

    /**
     * 判断是否存在光传感器来判断是否为模拟器
     * 部分真机也不存在温度和压力传感器。其余传感器模拟器也存在。
     */
    private CheckResult checkLightSensor() {
        SensorManager sensorManager = (SensorManager) application.getSystemService(SENSOR_SERVICE);
        Sensor sensor = sensorManager.getDefaultSensor(Sensor.TYPE_LIGHT); //光线传感器
        if (null == sensor) return addCheckResult("LightSensor", false, "可能是模拟器，不存在光传感器", 0.5);
        else return addCheckResult("LightSensor", true, "存在光传感器", 0.2);
    }

    /**
     * 特征参数-进程组信息
     */
    private CheckResult checkCgroup() {
        String filter = exec("cat /proc/self/cgroup");
        if (null == filter || filter.length() < 3)
            return addCheckResult("cgroup", false, "进程组信息为null", 0.4);
        return addCheckResult("cgroup", true, "进程组信息" + filter, 0.4);
    }

}
