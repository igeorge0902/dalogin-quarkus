package com.dalogin.listeners;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2015
 */

import com.dalogin.utils.PropertyUtils;
import com.google.common.collect.Multimap;
import com.google.common.collect.Multimaps;
import com.google.common.collect.TreeMultimap;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;
import org.jboss.logging.Logger;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

@WebListener
public class CustomServletContextListener implements ServletContextListener {
    public static String gmail_password = null;
    public static String gmail_username = null;
    public static String gmail_smtp = null;

    private static final Logger log = Logger.getLogger(CustomServletContextListener.class);

    /**
     *
     */
    public void contextInitialized(ServletContextEvent event) {
        log.debugf("event=CONTEXT_INIT listenerName=%s", CustomServletContextListener.class.getSimpleName());
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
    }

    public void contextDestroyed(ServletContextEvent event) {
        log.debugf("event=CONTEXT_DESTROY listenerName=%s", CustomServletContextListener.class.getSimpleName());
    }
}
