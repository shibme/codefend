package me.shib.security.codefender;

public final class CodefenderException extends RuntimeException {
    public CodefenderException(String message) {
        super(message);
    }

    public CodefenderException(Exception e) {
        super(e.getMessage(), e.getCause());
    }
}