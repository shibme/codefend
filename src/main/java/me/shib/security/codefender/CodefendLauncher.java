package me.shib.security.codefender;

import me.shib.security.codefender.scanners.javascript.retirejs.RetirejsScanner;
import me.shib.security.codefender.scanners.ruby.brakeman.BrakemanScanner;
import me.shib.security.codefender.scanners.ruby.bundleraudit.BundlerAudit;

public final class CodefendLauncher {
    public static void main(String[] args) {
        System.out.println("Codefender: Starting independent run");
        CodefenderConfig config = CodefenderConfig.getInstance();
        Codefender.addScanner(new BrakemanScanner(config));
        Codefender.addScanner(new BundlerAudit(config));
        Codefender.addScanner(new RetirejsScanner(config));
        Codefender.start(config);
    }
}
