package com.dalogin.persistence;

/**
 * Signals that a persistence family bean failed to complete an operation, carrying the failed
 * operation name and the identifier involved so callers can invalidate pending state and log
 * without secrets. Replaces the discardable {@code boolean}/{@code null} failure signals used by
 * the former {@code SQLAccess} static methods for the atomic device/session establishment path.
 */
public class PersistenceOperationException extends RuntimeException {

    private final String operation;
    private final String identifier;

    public PersistenceOperationException(String operation, String identifier, Throwable cause) {
        super("Persistence operation failed: operation=" + operation + ", identifier=" + identifier, cause);
        this.operation = operation;
        this.identifier = identifier;
    }

    public String operation() {
        return operation;
    }

    public String identifier() {
        return identifier;
    }
}
