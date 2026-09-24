package com.dalogin.persistence.support;

import org.jboss.logging.Logger;
import org.json.JSONObject;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.UUID;

/**
 * Shared, connection-free helpers used by every persistence family bean. Moved verbatim from
 * the former {@code SQLAccess} static helpers, plus the failure-path cleanup helpers required by
 * the CDI/family split.
 */
public final class SqlSupport {

    private static final Logger log = Logger.getLogger(SqlSupport.class);

    private SqlSupport() {
    }

    public static UUID generateUUID() {
        return UUID.randomUUID();
    }

    public static void logSQLException(SQLException ex) {
        for (Throwable e : ex) {
            if (e instanceof SQLException) {
                if (!ignoreSQLException(((SQLException) e).getSQLState())) {
                    e.printStackTrace(System.err);
                    System.err.println("SQLState: " + ((SQLException) e).getSQLState());
                    System.err.println("Error Code: " + ((SQLException) e).getErrorCode());
                    System.err.println("Message: " + e.getMessage());
                    Throwable t = ex.getCause();
                    while (t != null) {
                        System.out.println("Cause: " + t);
                        t = t.getCause();
                    }
                }
            }
        }
    }

    public static boolean ignoreSQLException(String sqlState) {
        if (sqlState == null) {
            System.out.println("The SQL state is not defined!");
            return false;
        }
        return sqlState.equalsIgnoreCase("42Y55");
    }

    public static JSONObject jsonSQLError(SQLException ex) {
        JSONObject json = new JSONObject();
        for (Throwable e : ex) {
            if (e instanceof SQLException) {
                if (!ignoreSQLException(((SQLException) e).getSQLState())) {
                    json.put("SQLState", ((SQLException) e).getSQLState());
                    json.put("Error Code", ((SQLException) e).getErrorCode());
                    json.put("Message", ((SQLException) e).getMessage());
                }
            }
        }
        return json;
    }

    /**
     * Rolls back a transaction without masking the primary failure that triggered the rollback.
     */
    public static void rollbackQuietly(Connection conn, Exception cause) {
        try {
            conn.rollback();
        } catch (SQLException rollbackEx) {
            log.errorf(rollbackEx, "Rollback failed after primary failure: %s", cause.getMessage());
        }
    }

    /**
     * Restores auto-commit so the connection cannot return to the pool mid-transaction.
     */
    public static void restoreAutoCommit(Connection conn) {
        try {
            conn.setAutoCommit(true);
        } catch (SQLException e) {
            log.errorf(e, "Failed to restore autoCommit before releasing connection to the pool");
        }
    }
}
