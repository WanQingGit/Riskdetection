package qing.risk.detection.checker;

import java.lang.reflect.Field;

public class XposedChecker extends BaseChecker {

    private static final String XPOSED_HELPERS = "de.robv.android.xposed.XposedHelpers";
    private static final String XPOSED_BRIDGE = "de.robv.android.xposed.XposedBridge";

    /**
     * 通过检查是否已经加载了XP类来检测
     */
    public CheckResult checkXposedByLoadClass() {
        try {
            Class<?> aClass = ClassLoader.getSystemClassLoader() .loadClass(XPOSED_HELPERS);
//            Class<?> aClass = Class.forName(XPOSED_HELPERS);
//            Object xpHelperObj = getClass().getClassLoader().loadClass(XPOSED_HELPERS)
//                    .newInstance();
            return addCheckResult("XposedByLoadClass", false, XPOSED_HELPERS + ":" + aClass.getClassLoader());
        } catch (ClassNotFoundException e) {
        }

        try {
//            Class<?> aClass =ClassLoader .getSystemClassLoader() .loadClass(XPOSED_BRIDGE);
            Class<?> aClass = Class.forName(XPOSED_BRIDGE);
            return addCheckResult("XposedByLoadClass", false, XPOSED_BRIDGE + ":" + aClass.getClassLoader());
        } catch (ClassNotFoundException e) {
        }
        return addCheckResult("XposedByLoadClass", true, null,0.4);
    }

    /**
     * 通过主动抛出异常，检查堆栈信息来判断是否存在XP框架
     *
     * @return
     */
    public boolean checkXposedByThrow() {
        try {
            throw new Exception("gg");
        } catch (Exception e) {
            for (StackTraceElement stackTraceElement : e.getStackTrace()) {
                if (stackTraceElement.getClassName().contains(XPOSED_BRIDGE)) {
                    addCheckResult("XposedByThrow", false, stackTraceElement.getClassName());
                    return true;
                }
            }
            addCheckResult("XposedByThrow", true, null,0.5);
            return false;
        }
    }

    /**
     * 尝试关闭XP框架
     * 先通过isXposedExistByThrow判断有没有XP框架
     * 有的话先hookXP框架的全局变量disableHooks
     * <p>
     * 漏洞在，如果XP框架先hook了isXposedExistByThrow的返回值，那么后续就没法走了
     * 现在直接先hookXP框架的全局变量disableHooks
     *
     * @return 是否关闭成功的结果
     */
    public boolean tryShutdownXposed() {
        Field xpdisabledHooks = null;
        try {
            xpdisabledHooks = ClassLoader.getSystemClassLoader()
                    .loadClass(XPOSED_BRIDGE)
                    .getDeclaredField("disableHooks");
            xpdisabledHooks.setAccessible(true);
            xpdisabledHooks.set(null, Boolean.TRUE);
            return true;
        } catch (NoSuchFieldException | ClassNotFoundException | IllegalAccessException e) {
            e.printStackTrace();
            return false;
        }
    }


    /**
     * 去读maps检测是否加载类xposed 的so 和jar
     */
//    fun detectByMaps() {
//        val hashSet = HashSet<String>()
//        val buffer = CheckerUtil.readByBytes(FileInputStream("/proc/${Process.myPid()}/maps"))
//        buffer.toString().split("\n").forEach { line ->
//            if ((line.endsWith(".so") || line.endsWith(".jar"))
//                    && line.contains("xposed", true)
//            ) {
//                hashSet.add(line)
//                CheckerLog.d(TAG, "line $line")
//            }
//        }
//        if (hashSet.isNotEmpty()) {
//            result.addError("$TAG hit detectByMaps: 加载了 xposed 的so 和jar")
//        }
//        CheckerLog.e(TAG, "has Xposed lib ${hashSet.size}")
//    }

}
