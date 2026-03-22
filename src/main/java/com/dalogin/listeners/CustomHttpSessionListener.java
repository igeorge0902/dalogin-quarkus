package com.dalogin.listeners;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2015
 */

import com.dalogin.SQLAccess;
import com.google.common.collect.SetMultimap;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.annotation.WebListener;
import jakarta.servlet.http.*;
import org.apache.log4j.Logger;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 *
 * Listener to manage session attributes, session creation.
 *
 * Session is bound to deviceId, i.e. one device with identical id will always have one session.
 * Session-based calls for sensitive data are verified with tokens, therefore over-spawning sessionIds
 * at extreme condition are not considered an issue because the dB will store/overwrite the tokens for the same device id with the last sessionId.
 *
 * It is guaranteed to work in normal conditions.
 *
 */
@WebListener
public class CustomHttpSessionListener extends HttpServlet implements HttpSessionListener, Serializable, HttpSessionAttributeListener {
    private static final long serialVersionUID = -6951824749917799153L;
    private static final Logger log = Logger.getLogger(Logger.class.getName());

    // Instance-level maps for tracking attribute bindings within this listener.
    // These are used for correlating deviceId ↔ user across attributeAdded/Removed callbacks.
    private final TreeMap<String, String> attributes = new TreeMap<>();
    private final TreeMap<String, String> attributes_ = new TreeMap<>();

    public void init(ServletConfig config) {
    }

    private TreeMap<String, String> SetMappings(String name, String value) {
        attributes.put(name, value);
        Collection<String> fruits = attributes.values();
        log.info("Values: " + fruits);
        return attributes;
    }

    private String GetMappings(String name) {
        return attributes.get(name);
    }

    private TreeMap<String, String> SetMappings_(String name, String value) {
        attributes_.put(name, value);
        Collection<String> fruits_ = attributes_.values();
        log.info("Values_: " + fruits_);
        return attributes_;
    }

    private String GetMappings_(String name) {
        return attributes_.get(name);
    }

    @SuppressWarnings("unchecked")
    @Override
    public void attributeAdded(HttpSessionBindingEvent se) {
        // Quarkus CDI may store internal objects (e.g. ComputingCache) as session attributes;
        // skip processing for non-String values to avoid ClassCastException.
        if (!(se.getValue() instanceof String)) {
            log.info("Skipping non-String session attribute: " + se.getName()
                    + " (type: " + se.getValue().getClass().getName() + ")");
            return;
        }
        HttpSession session = se.getSession();
        ServletContext context = session.getServletContext();
        ConcurrentHashMap<String, HttpSession> activeUsers = (ConcurrentHashMap<String, HttpSession>) context.getAttribute("activeUsers");
        SetMultimap<String, String> sessions = (SetMultimap<String, String>) context.getAttribute("sessions");
        String id = session.getId();
        String name = se.getName();
        String value = (String) se.getValue();
        log.info("Name: " + attributes.keySet() + "Value: " + attributes.values());
        String source = se.getSource().getClass().getName();
        String message = new StringBuffer("Attribute bound to session in ")
                .append(source).append("\nThe attribute name: ").append(name)
                .append("\n").append("The attribute value:").append(value)
                .append("\n").append("The session ID: ").append(id).toString();
        log.info(message);
        SetMappings(name, value);
        String D = GetMappings("deviceId");
        String useR = GetMappings("user");

        // ── Enforce one session per deviceId ──────────────────────────
        // When the "deviceId" attribute is set, evict any previous session
        // that was bound to the same device.
        if ("deviceId".equals(name) && D != null) {
            Set<String> oldEntries = sessions.get(D);
            if (oldEntries != null && !oldEntries.isEmpty()) {
                // Collect session IDs from the multimap (values that look like session IDs, not usernames)
                List<String> oldSessionIds = new java.util.ArrayList<>();
                for (String entry : oldEntries) {
                    // The multimap stores both the username and the sessionId under the deviceId key.
                    // Session IDs are present in activeUsers; usernames are not.
                    if (activeUsers.containsKey(entry) && !entry.equals(id)) {
                        oldSessionIds.add(entry);
                    }
                }
                for (String oldSid : oldSessionIds) {
                    HttpSession oldSession = activeUsers.remove(oldSid);
                    if (oldSession != null) {
                        log.info("Evicting previous session for deviceId=" + D + ": " + oldSid);
                        try {
                            oldSession.invalidate();
                        } catch (IllegalStateException ignored) {
                            // already invalidated
                        }
                    }
                }
                // Clear old multimap entries for this device — will be re-added below
                sessions.removeAll(D);
            }
        }

        // It will be null at first time.
        try {
            sessions.put(D, useR);
            sessions.put(D, id);
        } catch (Exception e) {
            log.info(e.getMessage());
        }
        activeUsers.put(session.getId(), session);
        log.info("SessionUsers: " + sessions.entries());
        log.info("Active UserSessions (attribute Added): " + activeUsers.keySet().toString());
    }

    @Override
    public void attributeRemoved(HttpSessionBindingEvent se) {
        // Quarkus CDI may store internal objects as session attributes;
        // skip processing for non-String values to avoid ClassCastException.
        if (!(se.getValue() instanceof String)) {
            log.info("Skipping non-String session attribute removal: " + se.getName()
                    + " (type: " + se.getValue().getClass().getName() + ")");
            return;
        }
        HttpSession session = se.getSession();
        @SuppressWarnings("unchecked")
        ConcurrentHashMap<String, HttpSession> activeUsers = (ConcurrentHashMap<String, HttpSession>) session.getServletContext().getAttribute("activeUsers");
        @SuppressWarnings("unchecked")
        SetMultimap<String, String> sessions = (SetMultimap<String, String>) session.getServletContext().getAttribute("sessions");
        String id = session.getId();
        String name = se.getName();
        if (name == null)
            name = "Unknown";
        String value = (String) se.getValue();
        String source = se.getSource().getClass().getName();
        String message = new StringBuffer("Attribute unbound from session in ")
                .append(source).append("\nThe attribute name: ").append(name)
                .append("\n").append("The attribute value: ").append(value)
                .append("\n").append("The session ID: ").append(id).toString();
        log.info(message);
        SetMappings_(name, value);
        String D_ = GetMappings_("deviceId");
        // removes existing sessionId
        activeUsers.remove(id);
        log.info("deviceId_ &sessioId at remove: " + D_ + "," + id);
        try {
            // removes deviceId from helper list (sessions Multimap is a helper list, but is able to list the active users )
            sessions.removeAll(D_);
        } catch (Exception e) {
            // error handling for empty leafs
            log.info("There was no device left over to remove...");
        }
        log.info("SessionUsers (attributeRemoved): " + sessions.entries());
    }

    @Override
    public void attributeReplaced(HttpSessionBindingEvent arg0) {
    }

    @SuppressWarnings("unchecked")
    public void sessionCreated(HttpSessionEvent event) {
        HttpSession session = event.getSession();
        ServletContext context = session.getServletContext();
        log.info("Context attributes: " + context.getAttributeNames().nextElement());
        ConcurrentHashMap<String, HttpSession> activeUsers = (ConcurrentHashMap<String, HttpSession>) context.getAttribute("activeUsers");
        SetMultimap<String, String> sessions = (SetMultimap<String, String>) context.getAttribute("sessions");
        String D = GetMappings("deviceId");
        // when creating a new session, if it's a new device, add user and sessionId tied to deviceId
        if (!sessions.containsKey(D)) {
            activeUsers.put(session.getId(), session);
            log.info("sessionId addded in event context: " + session.getId());
        }
        log.info("Active UserSessions (session Created): " + activeUsers.keySet().toString());
    }

    @SuppressWarnings("unchecked")
    public void sessionDestroyed(HttpSessionEvent event) {
        HttpSession session = event.getSession();
        if (session != null && session.getAttribute("deviceId") != null) {
            ServletContext context = session.getServletContext();
            ConcurrentHashMap<String, HttpSession> activeUsers = (ConcurrentHashMap<String, HttpSession>) context.getAttribute("activeUsers");
            SetMultimap<String, String> sessions = (SetMultimap<String, String>) context.getAttribute("sessions");
            String D_ = session.getAttribute("deviceId").toString();
            String id = session.getId();
            log.info("deviceId_ at destroy: " + D_);
            activeUsers.remove(session.getId());
            sessions.removeAll(D_);
            // runs logging out to make the user look like logged_out
            try {
                SQLAccess.logout(session.getId(), context);
            } catch (Exception e) {
                // error handling for empty leafs
                log.info("There was no device left over to remove...");
            }
            log.info("device logging out from SessionUsers: " + D_);
            log.info("SessionUsers left: " + sessions.entries());
            log.info("Active UserSessions left: " + activeUsers.keySet().toString());
            String message = new StringBuffer("Session destroyed"
                    + "\nValue of destroyed session ID is").append(" " + id).append(
                            "\n").append("There are now ").append("" + activeUsers.size())
                    .append(" live sessions in the application.").toString();
            log.info(message);
        }
    }
}
