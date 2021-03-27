package qing.risk.detection.checker;

import android.app.Application;
import android.util.Log;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import qing.risk.detection.MyApplication;


public abstract class BaseChecker {

    protected Map<String, CheckResult> checkItems = new HashMap<>();
    protected Map<String, CheckResult> checkItemsNotPass = new HashMap<>();
    private int flags = 0;
    private double negativeScore = 0;
    private double positiveScore = 0;
    public final Application application;


    public BaseChecker() {
        this(MyApplication.getMyApplication());
    }

    public BaseChecker(Application application) {
        this.application = application;
    }

    public static final int FLAG_NOT_PASS = 1;
    public static final int FLAG_PASS = 2;

    public void addCheckResult(CheckResult checkResult) {
        String key = checkResult.name;
        if (checkItems.containsKey(key)) {
            CheckResult checkResult2 = checkItems.get(key);
            if (checkResult2.weight != checkResult.weight || checkResult.pass != checkResult2.pass)
                Log.w("QING", "add the same checkResult with different value");
            return;
        }
        checkItems.put(key, checkResult);
        if (!checkResult.pass) {
            checkItemsNotPass.put(key, checkResult);
            negativeScore += checkResult.weight;
            if (checkResult.weight == 1.0) {
                if ((flags & FLAG_PASS) != 0)
                    throw new RuntimeException("invalid check item" + key);
                flags |= FLAG_NOT_PASS;
            }
        } else {
            if (checkResult.weight == 1.0) {
                if ((flags & FLAG_NOT_PASS) != 0)
                    throw new RuntimeException("invalid check item" + key);
                flags |= FLAG_PASS;
            }
            positiveScore += checkResult.weight;
        }
    }

    public CheckResult addCheckResult(String name, boolean pass, String des) {
        CheckResult checkResult = new CheckResult(name, pass, des);
        addCheckResult(checkResult);
        return checkResult;
    }
    public CheckResult addCheckResult(String name, boolean pass, String des, double weight) {
        CheckResult checkResult = new CheckResult(name, pass, des);
        checkResult.setWeight(weight);
        addCheckResult(checkResult);
        return checkResult;
    }

    public void init() {
        flags = 0;
        negativeScore = 0;
        positiveScore = 0;
        checkItems.clear();
        checkItemsNotPass.clear();
    }

    public final boolean startCheck() {
        init();
        Method[] declaredMethods = this.getClass().getDeclaredMethods();
        int prevSize = checkItems.size();
        for (Method method : declaredMethods) {
            String name = method.getName();
            if (name.startsWith("check")) {
                try {
                    method.setAccessible(true);
                    method.invoke(this);
                    int currentSize = checkItems.size();
                    if (currentSize == prevSize) {
                        Log.w("QING", "call the method " + method.getName() + " but not add check result!");
                    } else {
                        prevSize = currentSize;
                    }
                } catch (IllegalAccessException | InvocationTargetException e) {
                    e.printStackTrace();
                }
            }
        }
        try {
            return isPass();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean isPass() throws Exception {
        if (flags != 0) {
            if (flags == (FLAG_PASS | FLAG_NOT_PASS))
                throw new Exception("invalid result,can not both has pass and not pass flags");
            return (flags & FLAG_PASS) != 0;
        }
        int size = checkItemsNotPass.size();
        int size2 = checkItems.size() - size;
        if (size > 0 && size2 > 0) {
            double negativeAverScore = negativeScore / size;
            double positiveAverScore = positiveScore / size2;
            return positiveAverScore >= negativeAverScore;
        }
        return size2 > 0;
    }

    public void getCheckResultSummary(StringBuilder builder) {
        for (Map.Entry<String, CheckResult> checkResult : checkItems.entrySet()) {
            CheckResult value = checkResult.getValue();
            builder.append(value.name + "|" + value.pass + "|" + value.weight + "|" + value.desc + "\n");
        }
        builder.append("negativeScore:" + negativeScore + "\tpositiveScore:" + positiveScore + "\n");
    }
}
