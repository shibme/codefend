package me.shib.security.codefend;

public final class CodefendException extends RuntimeException {
    public CodefendException(String message) {
        super(message);
    }

    public CodefendException(Exception e) {
        super(e.getMessage(), e.getCause());
    }
}