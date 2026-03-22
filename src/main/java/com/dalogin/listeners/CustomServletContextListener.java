package com.dalogin.listeners;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2015
 */

import com.dalogin.DBConnectionManager;
import com.dalogin.utils.PropertyUtils;
import com.google.common.collect.Multimap;
import com.google.common.collect.Multimaps;
import com.google.common.collect.TreeMultimap;
import jakarta.inject.Inject;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;
import org.apache.log4j.Logger;

import javax.sql.DataSource;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

@WebListener
public class CustomServletContextListener implements ServletContextListener {
    public static String gmail_password = null;
    public static String gmail_username = null;
    public static String gmail_smtp = null;

    private static final Logger log = Logger.getLogger(Logger.class.getName());

    @Inject
    DataSource dataSource;

    /**
     *
     */
    public void contextInitialized(ServletContextEvent event) {
        ServletContext context = event.getServletContext();
        try {
            ClassLoader cl = this.getClass().getClassLoader();
            InputStream is = cl.getResourceAsStream("properties.properties");
            DataInputStream in = new DataInputStream(is);
            BufferedReader br = new BufferedReader(new InputStreamReader(in));
            PropertyUtils.loadPropertyFile("properties.properties", br);
            gmail_password = PropertyUtils.getProperty("gmail_password");
            gmail_username = PropertyUtils.getProperty("gmail_username");
            gmail_smtp = PropertyUtils.getProperty("gmail_smtp");
            in.close();
            br.close();
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }

        // Use Quarkus Agroal pooled DataSource instead of raw DriverManager connections.
        // Falls back to legacy DriverManager if CDI injection is not available.
        DBConnectionManager dbManager;
        if (dataSource != null) {
            dbManager = new DBConnectionManager(dataSource);
            log.info("Database connection pool initialized (Quarkus Agroal DataSource).");
        } else {
            String dbUrl = System.getenv().getOrDefault("DB_URL", "jdbc:mysql://localhost:3306/login_");
            dbManager = new DBConnectionManager(dbUrl, "sqluser", "sqluserpw");
            log.info("Database connection initialized (legacy DriverManager).");
        }
        context.setAttribute("DBManager", dbManager);

        /*
         * timeOut parameter for session creation (& to prevent playback attacks)
         */
        final String time = context.getInitParameter("TIME");
        context.setAttribute("time", time);
        //
        // instanciate a map to store references to all the active
        // sessions and bind it to context scope.
        //
        ConcurrentHashMap<String, Object> activeUsers = new ConcurrentHashMap<String, Object>();
        context.setAttribute("activeUsers", activeUsers);
        HashMap<String, String> attributes = new HashMap<String, String>();
        context.setAttribute("attributes", attributes);
        Multimap<String, String> sessions = Multimaps.synchronizedSortedSetMultimap(TreeMultimap.create());
        context.setAttribute("sessions", sessions);
        //PBI: resolve dependencies for WildFly, smoothly
        //WS SOAP taken out due to dependency conflict on WildFly.
        //put it here
    }

    /**
     * Needed for the ServletContextListener interface.
     */
    public void contextDestroyed(ServletContextEvent event) {
        // To overcome the problem with losing the session references
        // during server restarts, put code here to serialize the
        // activeUsers HashMap.  Then put code in the contextInitialized
        // method that reads and reloads it if it exists...
        ServletContext context = event.getServletContext();
        DBConnectionManager dbManager = (DBConnectionManager) context.getAttribute("DBManager");
        try {
            dbManager.closeConnection();
        } catch (SQLException e) {
            log.error(e.getLocalizedMessage());
        }
        log.info("Database connection closed for Application.");
    }
}
