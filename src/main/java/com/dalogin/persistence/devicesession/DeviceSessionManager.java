package com.dalogin.persistence.devicesession;

import com.dalogin.persistence.PersistenceOperationException;
import com.dalogin.persistence.support.SqlSupport;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import javax.sql.DataSource;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Device / session / token family. Merged per {@code FR-017}: {@code insert_sessionCreated} and
 * {@code logout_device} both write {@code device_states}, {@code logout_device} also writes
 * {@code Tokens}, and {@code get_token2} reads {@code Tokens JOIN Last_seen}.
 */
@ApplicationScoped
public class DeviceSessionManager {

    @Inject
    DataSource dataSource;

    /**
     * Atomically inserts the device row, the session-created row, and reads back the rotated
     * token pair on one connection so a session-insert or token-read failure rolls back the
     * device write too. Resolves the former open device-row disposition question: normal login
     * never leaves a partially established device/session pair.
     */
    public SessionTokens establishLogin(String deviceId, String user, long sessionCreated, String sessionId) {
        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(false);
            try {
                insertDevice(conn, deviceId, user);
                insertSessionCreated(conn, deviceId, sessionCreated, sessionId);
                SessionTokens tokens = getToken2(conn, deviceId);
                conn.commit();
                return tokens;
            } catch (SQLException | RuntimeException e) {
                SqlSupport.rollbackQuietly(conn, e);
                throw new PersistenceOperationException("establishLogin", deviceId, e);
            } finally {
                SqlSupport.restoreAutoCommit(conn);
            }
        } catch (SQLException e) {
            throw new PersistenceOperationException("establishLogin", deviceId, e);
        }
    }

    public boolean insertDevice(String deviceId, String user) {
        try (Connection conn = dataSource.getConnection()) {
            insertDevice(conn, deviceId, user);
            return true;
        } catch (SQLException ex) {
            SqlSupport.logSQLException(ex);
            return false;
        }
    }

    /** Never acquires, closes, commits, or rolls back {@code conn}. */
    public void insertDevice(Connection conn, String deviceId, String user) throws SQLException {
        try (CallableStatement statement = conn.prepareCall("{call `insert_device_`(?, ?)}")) {
            statement.setString(1, deviceId);
            statement.setString(2, user);
            statement.executeUpdate();
        }
    }

    public boolean insertSessionCreated(String deviceId, long sessionCreated, String sessionId) {
        try (Connection conn = dataSource.getConnection()) {
            insertSessionCreated(conn, deviceId, sessionCreated, sessionId);
            return true;
        } catch (SQLException ex) {
            SqlSupport.logSQLException(ex);
            return false;
        }
    }

    /** Never acquires, closes, commits, or rolls back {@code conn}. */
    public void insertSessionCreated(Connection conn, String deviceId, long sessionCreated, String sessionId)
            throws SQLException {
        try (CallableStatement statement = conn.prepareCall("{call `insert_sessionCreated`(?, ?, ?)}")) {
            statement.setString(1, deviceId);
            statement.setLong(2, sessionCreated);
            statement.setString(3, sessionId);
            statement.executeUpdate();
        }
    }

    public String getToken(String deviceId) {
        try (Connection conn = dataSource.getConnection()) {
            try (CallableStatement statement = conn.prepareCall("{call `get_token`(?)}")) {
                statement.setString(1, deviceId);
                try (ResultSet rs = statement.executeQuery()) {
                    return rs.next() ? rs.getString(1) : null;
                }
            }
        } catch (SQLException ex) {
            SqlSupport.logSQLException(ex);
            return null;
        }
    }

    /**
     * Standalone form preserved for existing verified callers; returns an empty list when no
     * token row exists yet, matching the former {@code SQLAccess.getToken2} baseline exactly.
     */
    public List<String> getToken2(String deviceId) {
        List<String> list = new ArrayList<>();
        try (Connection conn = dataSource.getConnection()) {
            try (CallableStatement statement = conn.prepareCall("{call `get_token2`(?)}")) {
                statement.setString(1, deviceId);
                try (ResultSet rs = statement.executeQuery()) {
                    if (rs.next()) {
                        list.add(rs.getString(1));
                        list.add(rs.getString(2));
                    }
                }
            }
        } catch (SQLException ex) {
            SqlSupport.logSQLException(ex);
        }
        return list;
    }

    /**
     * Connection-accepting form used only inside an owning transaction (e.g. {@code
     * establishLogin}, {@code wrapUpRegistration}). Absence of a token row here is a hard
     * persistence failure, not the asynchronous-commit race the old 100 ms retry worked around.
     */
    public SessionTokens getToken2(Connection conn, String deviceId) throws SQLException {
        try (CallableStatement statement = conn.prepareCall("{call `get_token2`(?)}")) {
            statement.setString(1, deviceId);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    throw new SQLException("Session token was not created");
                }
                return new SessionTokens(resultSet.getString(1), resultSet.getString(2));
            }
        }
    }

    /**
     * Logout ownership and the affected-row-count signal are reworked in
     * {@code dalogin-login-logout-error-handling}, which runs after this pass; this method keeps
     * the current boolean success signal and {@code executeQuery()} call unchanged.
     */
    public boolean logout(String sessionId) {
        try (Connection conn = dataSource.getConnection()) {
            try (CallableStatement statement = conn.prepareCall("{call `logout_device`(?)}")) {
                statement.setString(1, sessionId);
                statement.executeQuery();
            }
            return true;
        } catch (SQLException ex) {
            SqlSupport.logSQLException(ex);
            return false;
        }
    }
}
