package com.schibsted.spt.identity.spidjavaapiexplorer.exception;

public class ServletControllerException extends Exception {
    public ServletControllerException(String message) {
        super(message);
    }

    public ServletControllerException(Throwable throwable) {
        super(throwable);
    }

    public ServletControllerException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
