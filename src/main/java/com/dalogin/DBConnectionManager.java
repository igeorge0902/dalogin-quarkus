package com.dalogin;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2015
 */

import org.apache.log4j.Logger;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;

/**
 * Database connection manager backed by a pooled DataSource.
 *
 * When constructed with a DataSource (Quarkus Agroal), connections are obtained
 * from the pool — thread-safe and properly bounded.
 *
 * The legacy (url, user, password) constructor is kept for backwards compatibility
 * but should not be used in production; it creates unpooled connections via DriverManager.
 */
public class DBConnectionManager {

    private static final Logger log = Logger.getLogger(Logger.class.getName());

    private DataSource dataSource;

    // Legacy fields — only used when no DataSource is available
    private String dbURL;
    private String user;
    private String password;

    public DBConnectionManager() {
    }

    /**
     * Preferred constructor — uses a pooled DataSource (Quarkus Agroal).
     */
    public DBConnectionManager(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    /**
     * Legacy constructor — creates unpooled DriverManager connections.
     * Kept for backwards compatibility.
     */
    public DBConnectionManager(String url, String u, String p) {
        this.dbURL = url;
        this.user = u;
        this.password = p;
    }

    /**
     * Returns a connection from the pool (DataSource) or creates one via DriverManager (legacy).
     * Callers MUST close the returned connection (use try-with-resources).
     */
    public Connection getConnection() throws SQLException, ClassNotFoundException {
        if (dataSource != null) {
            Connection conn = dataSource.getConnection();
            log.info("Connection obtained from pool (catalog: " + conn.getCatalog() + ")");
            return conn;
        }

        // Legacy fallback — no pooling, no thread safety
        Class.forName("com.mysql.cj.jdbc.Driver");
        Connection conn = java.sql.DriverManager.getConnection(dbURL, user, password);
        String catalog = SystemConstants.DB_CATALOG;
        conn.setCatalog(catalog);
        conn.setAutoCommit(true);
        log.info("dB Connection created (legacy), catalog set to \"" + catalog + "\"");
        return conn;
    }

    /**
     * No-op when using a pooled DataSource. Individual connections are closed by callers.
     */
    public void closeConnection() throws SQLException {
        // DataSource-managed connections are returned to the pool when closed by callers.
        // Nothing to do here.
    }
}
