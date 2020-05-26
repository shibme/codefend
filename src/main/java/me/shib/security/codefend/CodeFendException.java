package me.shib.security.codefend;

public final class CodeFendException extends RuntimeException {
    public CodeFendException(String message) {
        super(message);
    }

    public CodeFendException(Exception e) {
        super(e.getMessage(), e.getCause());
    }
}