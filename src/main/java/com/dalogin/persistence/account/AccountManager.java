package com.dalogin.persistence.account;

import com.dalogin.persistence.devicesession.DeviceSessionManager;
import com.dalogin.persistence.support.SqlSupport;
import com.dalogin.persistence.voucher.VoucherManager;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import javax.sql.DataSource;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Login / registration family. Registration and login are one family (`OQ-001` settled), so
 * {@code wrapUpRegistration} is owned here rather than by an orchestration layer above families.
 */
@ApplicationScoped
public class AccountManager {

    @Inject
    DataSource dataSource;

    @Inject
    VoucherManager voucherManager;

    @Inject
    DeviceSessionManager deviceSessionManager;

    public String createUser(String pass, String user, String email) {
        try (Connection conn = dataSource.getConnection()) {
            String sql = "INSERT INTO logins VALUES (default, ?, ?, default, ?, default, default)";
            try (PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
                pstmt.setString(1, pass);
                pstmt.setString(2, user);
                pstmt.setString(3, email);
                pstmt.executeUpdate();
            }
        } catch (SQLException ex) {
            SqlSupport.logSQLException(ex);
            return SqlSupport.jsonSQLError(ex).toString();
        }
        return "I";
    }

    public boolean changePassword(String pass, String email) {
        try (Connection conn = dataSource.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `update_password`(?, ?)}")) {
                cstmt.setString(1, pass);
                cstmt.setString(2, email);
                cstmt.executeUpdate();
            }
        } catch (SQLException ex) {
            SqlSupport.logSQLException(ex);
            return false;
        }
        return true;
    }

    /**
     * Atomic registration-with-voucher transaction. The fixed order is a schema/trigger contract:
     * insert_voucher -&gt; insert_device_ (device_states trigger) -&gt; insert_sessionCreated
     * (Tokens via Last_seen trigger) -&gt; copy_token2. Cross-family participants never acquire,
     * close, commit, or roll back the connection passed to them.
     */
    public boolean wrapUpRegistration(String voucher, String user, String password, String deviceId,
                                       long sessionCreated, String sessionId) {
        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(false);
            try {
                voucherManager.insertVoucher(conn, voucher, user, password);
                deviceSessionManager.insertDevice(conn, deviceId, user);
                deviceSessionManager.insertSessionCreated(conn, deviceId, sessionCreated, sessionId);
                voucherManager.copyToken2(conn, voucher);
                conn.commit();
                return true;
            } catch (SQLException e) {
                SqlSupport.rollbackQuietly(conn, e);
                return false;
            } finally {
                SqlSupport.restoreAutoCommit(conn);
            }
        } catch (SQLException e) {
            SqlSupport.logSQLException(e);
            return false;
        }
    }

    public String checkActivation(String user) {
        String response = null;
        try (Connection conn = dataSource.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `isActivated`(?)}")) {
                cstmt.setString(1, user);
                try (ResultSet rs = cstmt.executeQuery()) {
                    if (rs.next()) {
                        response = rs.getInt(1) != 1 ? "S" : "";
                    }
                }
            }
        } catch (SQLException ex) {
            SqlSupport.logSQLException(ex);
        }
        return response;
    }

    public String getUUID(String user) {
        String uuid = null;
        try (Connection conn = dataSource.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `get_uuid`(?)}")) {
                cstmt.setString(1, user);
                try (ResultSet rs = cstmt.executeQuery()) {
                    if (rs.next()) {
                        uuid = rs.getString(1);
                    }
                }
            }
        } catch (SQLException ex) {
            SqlSupport.logSQLException(ex);
        }
        return uuid;
    }

    public String getHash(String pass, String user) {
        String hash = null;
        try (Connection conn = dataSource.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `get_hash`(?, ?)}")) {
                cstmt.setString(1, pass);
                cstmt.setString(2, user);
                try (ResultSet rs = cstmt.executeQuery()) {
                    if (rs.next()) {
                        hash = rs.getString(1);
                    }
                }
            }
        } catch (SQLException ex) {
            SqlSupport.logSQLException(ex);
        }
        return hash;
    }

    public boolean deleteUser(String user) {
        try (Connection conn = dataSource.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `delete_user`(?)}")) {
                cstmt.setString(1, user);
                cstmt.executeQuery();
            }
            return true;
        } catch (SQLException ex) {
            SqlSupport.logSQLException(ex);
            return false;
        }
    }
}
