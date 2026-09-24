package com.dalogin.persistence.passwordreset;

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
 * Password reset family: reset-token issuance and confirmation-code retrieval.
 */
@ApplicationScoped
public class PasswordResetManager {

    @Inject
    DataSource dataSource;

    public String getForgotPswToken(String email, long time) {
        String forgotPswToken = null;
        try (Connection conn = dataSource.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `find_email`(?)}")) {
                cstmt.setString(1, email);
                try (ResultSet rs = cstmt.executeQuery()) {
                    if (rs.next()) {
                        String emailFromDB = rs.getString(1);
                        if (email.equals(emailFromDB)) {
                            try (CallableStatement cstmt2 = conn.prepareCall("{call `forgot_password`(?, ?)}")) {
                                cstmt2.setString(1, email);
                                cstmt2.setLong(2, time);
                                try (ResultSet rs2 = cstmt2.executeQuery()) {
                                    if (rs2.next()) {
                                        forgotPswToken = rs2.getString(1);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch (SQLException ex) {
            SqlSupport.logSQLException(ex);
        }
        return forgotPswToken;
    }

    public List<String> getForgotPswConfirmationCode(String email) {
        List<String> forgotPswConfirmationCode = new ArrayList<>();
        try (Connection conn = dataSource.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `find_email2`(?)}")) {
                cstmt.setString(1, email);
                try (ResultSet rs = cstmt.executeQuery()) {
                    if (rs.next()) {
                        forgotPswConfirmationCode.add(rs.getString(1));
                        forgotPswConfirmationCode.add(rs.getString(2));
                    }
                }
            }
        } catch (SQLException ex) {
            SqlSupport.logSQLException(ex);
        }
        return forgotPswConfirmationCode;
    }
}
