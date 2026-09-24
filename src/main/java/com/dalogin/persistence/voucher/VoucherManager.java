package com.dalogin.persistence.voucher;

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
 * Voucher family. {@code copyToken2} is assigned here by owned table ({@code voucher_states}),
 * not by its token-shaped name (`OQ-003`-adjacent boundary decision).
 */
@ApplicationScoped
public class VoucherManager {

    @Inject
    DataSource dataSource;

    public boolean checkVoucher(String voucher) {
        try (Connection conn = dataSource.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `get_voucher`(?)}")) {
                cstmt.setString(1, voucher);
                try (ResultSet rs = cstmt.executeQuery()) {
                    if (rs.next()) {
                        String voucherFromDB = rs.getString(1);
                        if (voucher.equals(voucherFromDB)) {
                            try (CallableStatement cstmt2 = conn.prepareCall("{call `set_voucher`(?)}")) {
                                cstmt2.setString(1, voucher);
                                cstmt2.executeQuery();
                            }
                            return true;
                        }
                    }
                }
            }
        } catch (SQLException ex) {
            SqlSupport.logSQLException(ex);
        }
        return false;
    }

    /**
     * Callerless wrapper carried forward unchanged (`OQ-003` settled: keep, do not delete);
     * delegates to the connection-accepting form so the SQL is written once.
     */
    public boolean insertVoucher(String voucher, String user, String pass) {
        try (Connection conn = dataSource.getConnection()) {
            insertVoucher(conn, voucher, user, pass);
            return true;
        } catch (SQLException ex) {
            SqlSupport.logSQLException(ex);
            return false;
        }
    }

    /** Never acquires, closes, commits, or rolls back {@code conn}. */
    public void insertVoucher(Connection conn, String voucher, String user, String pass) throws SQLException {
        try (CallableStatement cstmt = conn.prepareCall("{call `insert_voucher`(?, ?, ?)}")) {
            cstmt.setString(1, voucher);
            cstmt.setString(2, user);
            cstmt.setString(3, pass);
            cstmt.executeUpdate();
        }
    }

    /**
     * Callerless wrapper carried forward unchanged (`OQ-003` settled: keep, do not delete);
     * delegates to the connection-accepting form so the SQL is written once.
     */
    public boolean copyToken2(String voucher) {
        try (Connection conn = dataSource.getConnection()) {
            copyToken2(conn, voucher);
            return true;
        } catch (SQLException ex) {
            SqlSupport.logSQLException(ex);
            return false;
        }
    }

    /** Never acquires, closes, commits, or rolls back {@code conn}. */
    public void copyToken2(Connection conn, String voucher) throws SQLException {
        try (CallableStatement cstmt = conn.prepareCall("{call `copy_token2`(?)}")) {
            cstmt.setString(1, voucher);
            cstmt.executeUpdate();
        }
    }

    public boolean resetVoucher(String voucher, String user) {
        try (Connection conn = dataSource.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `reset_voucher`(?, ?)}")) {
                cstmt.setString(1, voucher);
                cstmt.setString(2, user);
                cstmt.executeQuery();
            }
            return true;
        } catch (SQLException ex) {
            SqlSupport.logSQLException(ex);
            return false;
        }
    }

    public boolean registerVoucher(String voucher) {
        try (Connection conn = dataSource.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `get_processing_voucher`(?)}")) {
                cstmt.setString(1, voucher);
                try (ResultSet rs = cstmt.executeQuery()) {
                    if (rs.next()) {
                        String voucherFromDB = rs.getString(1);
                        if (voucher.equals(voucherFromDB)) {
                            try (CallableStatement cstmt2 = conn.prepareCall("{call `register_voucher`(?)}")) {
                                cstmt2.setString(1, voucher);
                                cstmt2.executeQuery();
                            }
                            return true;
                        }
                    }
                }
            }
        } catch (SQLException ex) {
            SqlSupport.logSQLException(ex);
        }
        return false;
    }

    public List<String> getActivationToken(String user) {
        List<String> list = new ArrayList<>();
        try (Connection conn = dataSource.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `get_activation_vocher`(?)}")) {
                cstmt.setString(1, user);
                try (ResultSet rs = cstmt.executeQuery()) {
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

    public boolean activateVoucher(String activationToken, String user) {
        try (Connection conn = dataSource.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `activate_voucher`(?, ?)}")) {
                cstmt.setString(1, activationToken);
                cstmt.setString(2, user);
                cstmt.executeUpdate();
            }
            return true;
        } catch (SQLException ex) {
            SqlSupport.logSQLException(ex);
            return false;
        }
    }
}
