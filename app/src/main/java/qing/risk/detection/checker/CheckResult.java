package qing.risk.detection.checker;

public class CheckResult {
    String name;
    boolean pass;
    public double weight = 1;
    String desc;

    public CheckResult(String name, boolean pass, String desc) {
        this.name = name;
        this.pass = pass;
        this.desc = desc;
    }

    public CheckResult setWeight(double weight) {
        if (weight > 1.0) {
            weight=1.0;
        }else if(weight<0.0)
            weight=0;
        this.weight = weight;
        return this;
    }
}
