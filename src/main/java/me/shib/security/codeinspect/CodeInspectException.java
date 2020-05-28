package me.shib.security.codeinspect;

public final class CodeInspectException extends RuntimeException {
    public CodeInspectException(String message) {
        super(message);
    }

    public CodeInspectException(Exception e) {
        super(e.getMessage(), e.getCause());
    }
}