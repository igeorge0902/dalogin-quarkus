package com.dalogin;

import jakarta.servlet.ServletContext;
import org.apache.commons.io.IOUtils;
import org.json.JSONObject;

import java.io.*;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class SQLAccess {

    // Static fields
    private static volatile String hash;
    private static volatile String token;
    private static volatile String uuid;
    private static volatile String time;
    private static volatile String forgotPswToken;
    private static volatile List<String> forgotPswConfirmationCode;
    private static volatile String forgotRequestToken;
    private static volatile String forgotRequestTime;
    private static volatile Connection connect = null;
    private static volatile PreparedStatement preparedStatement = null;
    private static volatile UUID idOne;
    private static volatile String email;
    private static volatile List<String> list;
    private static volatile List<String> list_;
    private static volatile int isActivated;
    private static volatile String response = null;
    private static volatile ResultSet rs;
    private static volatile CallableStatement callableStatement = null;
    private static volatile CallableStatement callableStatement_ = null;

    // Helper method to generate UUID
    public synchronized static UUID generateUUID() {
        if (idOne == null) {
            idOne = UUID.randomUUID();
        }
        return idOne;
    }

    // Helper method to establish a database connection
    public synchronized static Connection connect(ServletContext context) throws ClassNotFoundException, SQLException {
        if (connect == null) {
            DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
            connect = dbManager.getConnection();
        }
        return connect;
    }

    // Helper method to log SQL exceptions
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

    // Helper method to ignore specific SQL exceptions
    public static boolean ignoreSQLException(String sqlState) {
        if (sqlState == null) {
            System.out.println("The SQL state is not defined!");
            return false;
        }
        return sqlState.equalsIgnoreCase("42Y55");
    }

    // Helper method to convert SQL exceptions to JSON
    private static JSONObject jsonSQLError(SQLException ex) {
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

    // Method to create a new user
    public synchronized static String createUser(String pass, String user, String email, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        try (Connection conn = dbManager.getConnection()) {
            String sql = "INSERT INTO logins VALUES (default, ?, ?, default, ?, default, default)";
            try (PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
                pstmt.setString(1, pass);
                pstmt.setString(2, user);
                pstmt.setString(3, email);
                pstmt.executeUpdate();
            }
        } catch (SQLException ex) {
            logSQLException(ex);
            return jsonSQLError(ex).toString();
        }
        return "I";
    }

    // Method to change user password
    public synchronized static boolean changePassword(String pass, String email, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        try (Connection conn = dbManager.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `update_password`(?, ?)}")) {
                cstmt.setString(1, pass);
                cstmt.setString(2, email);
                cstmt.executeUpdate();
            }
        } catch (SQLException ex) {
            logSQLException(ex);
            return false;
        }
        return true;
    }

    // Method to wrap up user registration
    public synchronized static boolean wrapUpRegistration(String voucher, String user, String pass, String deviceId, long sessionCreated, String sessionID, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        try (Connection conn = dbManager.getConnection()) {
            conn.setAutoCommit(false);

            // Insert voucher
                try (CallableStatement cstmt = conn.prepareCall("{call `insert_voucher`(?, ?, ?)}")) {
                    cstmt.setString(1, voucher);
                    cstmt.setString(2, user);
                    cstmt.setString(3, pass);
                    cstmt.executeUpdate();
                }

            // Insert device
                try (CallableStatement cstmt = conn.prepareCall("{call `insert_device_`(?, ?)}")) {
                    cstmt.setString(1, deviceId);
                    cstmt.setString(2, user);
                    cstmt.executeUpdate();
                }

            // Insert session
                try (CallableStatement cstmt = conn.prepareCall("{call `insert_sessionCreated`(?, ?, ?)}")) {
                    cstmt.setString(1, deviceId);
                    cstmt.setLong(2, sessionCreated);
                    cstmt.setString(3, sessionID);
                    cstmt.executeUpdate();
                }

            // Copy token
                try (CallableStatement cstmt = conn.prepareCall("{call `copy_token2`(?)}")) {
                    cstmt.setString(1, voucher);
                    cstmt.executeUpdate();
                }

            conn.commit();
            return true;
        } catch (SQLException ex) {
            logSQLException(ex);
            return false;
        }
    }

    // Method to check voucher state
    public synchronized static boolean checkVoucher(String voucher, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        try (Connection conn = dbManager.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `get_voucher`(?)}")) {
                cstmt.setString(1, voucher);
                ResultSet rs = cstmt.executeQuery();
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
        } catch (SQLException ex) {
            logSQLException(ex);
        }
        return false;
    }

    // Method to insert a voucher
    public synchronized static boolean insertVoucher(String voucher, String user, String pass, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        try (Connection conn = dbManager.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `insert_voucher`(?, ?, ?)}")) {
                cstmt.setString(1, voucher);
                cstmt.setString(2, user);
                cstmt.setString(3, pass);
                cstmt.executeUpdate();
            }
            return true;
        } catch (SQLException ex) {
            logSQLException(ex);
            return false;
        }
    }

    // Method to insert a device
    public synchronized static boolean insertDevice(String deviceId, String user, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        try (Connection conn = dbManager.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `insert_device_`(?, ?)}")) {
                cstmt.setString(1, deviceId);
                cstmt.setString(2, user);
                cstmt.executeUpdate();
            }
            return true;
        } catch (SQLException ex) {
            logSQLException(ex);
            return false;
        }
    }

    // Method to insert session creation time
    public synchronized static boolean insertSessionCreated(String deviceId, long sessionCreated, String sessionID, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        try (Connection conn = dbManager.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `insert_sessionCreated`(?, ?, ?)}")) {
                cstmt.setString(1, deviceId);
                cstmt.setLong(2, sessionCreated);
                cstmt.setString(3, sessionID);
                cstmt.executeUpdate();
            }
            return true;
        } catch (SQLException ex) {
            logSQLException(ex);
            return false;
        }
    }

    // Method to copy token2
    public synchronized static boolean copyToken2(String voucher, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        try (Connection conn = dbManager.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `copy_token2`(?)}")) {
                cstmt.setString(1, voucher);
                cstmt.executeUpdate();
            }
            return true;
        } catch (SQLException ex) {
            logSQLException(ex);
            return false;
        }
    }

    // Method to reset a voucher
    public synchronized static boolean resetVoucher(String voucher, String user, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        try (Connection conn = dbManager.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `reset_voucher`(?, ?)}")) {
                cstmt.setString(1, voucher);
                cstmt.setString(2, user);
                cstmt.executeQuery();
            }
            return true;
        } catch (SQLException ex) {
            logSQLException(ex);
            return false;
        }
    }

    // Method to delete a user
    public synchronized static boolean deleteUser(String user, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        try (Connection conn = dbManager.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `delete_user`(?)}")) {
                cstmt.setString(1, user);
                cstmt.executeQuery();
            }
            return true;
        } catch (SQLException ex) {
            logSQLException(ex);
            return false;
        }
    }

    // Method to register a voucher
    public synchronized static boolean registerVoucher(String voucher, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        try (Connection conn = dbManager.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `get_processing_voucher`(?)}")) {
                cstmt.setString(1, voucher);
                ResultSet rs = cstmt.executeQuery();
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
        } catch (SQLException ex) {
            logSQLException(ex);
        }
        return false;
    }

    // Method to get user hash
    public synchronized static String getHash(String pass, String user, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        try (Connection conn = dbManager.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `get_hash`(?, ?)}")) {
                cstmt.setString(1, pass);
                cstmt.setString(2, user);
                ResultSet rs = cstmt.executeQuery();
                if (rs.next()) {
                    hash = rs.getString(1);
                }
            }
        } catch (SQLException ex) {
            logSQLException(ex);
        }
        return hash;
    }

    // Method to get forgot password token
    public synchronized static String getForgotPswToken(String email, long time, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        try (Connection conn = dbManager.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `find_email`(?)}")) {
                cstmt.setString(1, email);
                ResultSet rs = cstmt.executeQuery();
                if (rs.next()) {
                    String emailFromDB = rs.getString(1);
                    if (email.equals(emailFromDB)) {
                        try (CallableStatement cstmt2 = conn.prepareCall("{call `forgot_password`(?, ?)}")) {
                            cstmt2.setString(1, email);
                            cstmt2.setLong(2, time);
                            ResultSet rs2 = cstmt2.executeQuery();
                            if (rs2.next()) {
                                forgotPswToken = rs2.getString(1);
                            }
                        }
                    }
                }
            }
        } catch (SQLException ex) {
            logSQLException(ex);
        }
        return forgotPswToken;
    }

    // Method to get forgot password confirmation code
    public synchronized static List<String> getForgotPswConfirmationCode(String email, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        forgotPswConfirmationCode = new ArrayList<>();
        try (Connection conn = dbManager.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `find_email2`(?)}")) {
                cstmt.setString(1, email);
                ResultSet rs = cstmt.executeQuery();
                if (rs.next()) {
                    forgotRequestToken = rs.getString(1);
                    forgotRequestTime = rs.getString(2);
                    forgotPswConfirmationCode.add(forgotRequestToken);
                    forgotPswConfirmationCode.add(forgotRequestTime);
                }
            }
        } catch (SQLException ex) {
            logSQLException(ex);
        }
        return forgotPswConfirmationCode;
    }

    // Method to check if a user is activated
    public synchronized static String checkActivation(String user, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        try (Connection conn = dbManager.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `isActivated`(?)}")) {
                cstmt.setString(1, user);
                ResultSet rs = cstmt.executeQuery();
                if (rs.next()) {
                    isActivated = rs.getInt(1);
                    if (isActivated != 1) {
                        response = "S";
                    } else {
                        response = "";
                    }
                }
            }
        } catch (SQLException ex) {
            logSQLException(ex);
        }
        return response;
    }

    // Method to get UUID for a user
    public synchronized static String getUUID(String user, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        try (Connection conn = dbManager.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `get_uuid`(?)}")) {
                cstmt.setString(1, user);
                ResultSet rs = cstmt.executeQuery();
                if (rs.next()) {
                    uuid = rs.getString(1);
                }
            }
        } catch (SQLException ex) {
            logSQLException(ex);
        }
        return uuid;
    }

    // Method to get token for a device
    public synchronized static String getToken(String deviceId, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        try (Connection conn = dbManager.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `get_token`(?)}")) {
                cstmt.setString(1, deviceId);
                ResultSet rs = cstmt.executeQuery();
                if (rs.next()) {
                    token = rs.getString(1);
                }
            }
        } catch (SQLException ex) {
            logSQLException(ex);
        }
        return token;
    }

    // Method to get token2 for a device
    public synchronized static List<String> getToken2(String deviceId, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        list_ = new ArrayList<>();
        try (Connection conn = dbManager.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `get_token2`(?)}")) {
                cstmt.setString(1, deviceId);
                ResultSet rs = cstmt.executeQuery();
                if (rs.next()) {
                    token = rs.getString(1);
                    time = rs.getString(2);
                    list_.add(token);
                    list_.add(time);
                }
            }
        } catch (SQLException ex) {
            logSQLException(ex);
        }
        return list_;
    }

    // Method to get activation token and email for a user
    public synchronized static List<String> getActivationToken(String user, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        list = new ArrayList<>();
        try (Connection conn = dbManager.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `get_activation_vocher`(?)}")) {
                cstmt.setString(1, user);
                ResultSet rs = cstmt.executeQuery();
                if (rs.next()) {
                    token = rs.getString(1);
                    email = rs.getString(2);
                    list.add(token);
                    list.add(email);
                }
            }
        } catch (SQLException ex) {
            logSQLException(ex);
        }
        return list;
    }

    // Method to activate a voucher
    public synchronized static boolean activateVoucher(String activationToken, String user, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        try (Connection conn = dbManager.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `activate_voucher`(?, ?)}")) {
                cstmt.setString(1, activationToken);
                cstmt.setString(2, user);
                cstmt.executeUpdate();
            }
            return true;
        } catch (SQLException ex) {
            logSQLException(ex);
            return false;
        }
    }

    // Method to log out a device
    public synchronized static boolean logout(String sessionID, ServletContext context) throws Exception {
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        try (Connection conn = dbManager.getConnection()) {
            try (CallableStatement cstmt = conn.prepareCall("{call `logout_device`(?)}")) {
                cstmt.setString(1, sessionID);
                cstmt.executeQuery();
            }
            return true;
        } catch (SQLException ex) {
            logSQLException(ex);
            return false;
        }
    }
}