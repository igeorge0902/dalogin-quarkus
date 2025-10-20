package com.dalogin;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2015
 */

import org.apache.log4j.Logger;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 *
 */
public class DBConnectionManager {
    /**
     *
     */
    private static Logger log = Logger.getLogger(Logger.class.getName());
    /**
     *
     */
    private String dbURL;
    /**
     *
     */
    private String user;
    /**
     *
     */
    private String password;
    /**
     *
     */
    private volatile Connection con;

    public DBConnectionManager() {
    }

    /**
     *
     * @param url
     * @param u
     * @param p
     */
    public DBConnectionManager(String url, String u, String p) {
        this.dbURL = url;
        this.user = u;
        this.password = p;
        //create db connection now
    }
    //TODO: add RabbitMQ Connection factory as below

    /**
     *
     * @return
     * @throws SQLException
     * @throws ClassNotFoundException
     */
    public Connection getConnection() throws SQLException, ClassNotFoundException {
        Class.forName("com.mysql.cj.jdbc.Driver");
        con = DriverManager.getConnection(dbURL, user, password);
        con.setCatalog("login_");
        con.setAutoCommit(true);
        log.info("dB Connection created, catalog set to \"login\"");
        return this.con;
    }

    /**
     *
     * @throws SQLException
     */
    public void closeConnection() throws SQLException {
        if (con != null) {
            con.close();
        }
    }
}