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
import java.util.List;
import java.util.Map;
import java.util.Set;
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

    // Per-session attribute tracking — keyed by session ID to avoid cross-thread pollution.
    // The old instance-level TreeMaps were shared across all concurrent attributeAdded/Removed
    // callbacks, so Thread A's deviceId was overwritten by Thread B.
    private final ConcurrentHashMap<String, Map<String, String>> sessionAttributes = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Map<String, String>> sessionAttributes_ = new ConcurrentHashMap<>();

    public void init(ServletConfig config) {
    }

    private Map<String, String> getSessionMap(String sessionId) {
        return sessionAttributes.computeIfAbsent(sessionId, k -> new ConcurrentHashMap<>());
    }

    private Map<String, String> getSessionMap_(String sessionId) {
        return sessionAttributes_.computeIfAbsent(sessionId, k -> new ConcurrentHashMap<>());
    }

    private void SetMappings(String sessionId, String name, String value) {
        Map<String, String> attrs = getSessionMap(sessionId);
        attrs.put(name, value);
        log.info("Values: " + attrs.values());
    }

    private String GetMappings(String sessionId, String name) {
        Map<String, String> attrs = sessionAttributes.get(sessionId);
        return (attrs != null) ? attrs.get(name) : null;
    }

    private void SetMappings_(String sessionId, String name, String value) {
        Map<String, String> attrs = getSessionMap_(sessionId);
        attrs.put(name, value);
        log.info("Values_: " + attrs.values());
    }

    private String GetMappings_(String sessionId, String name) {
        Map<String, String> attrs = sessionAttributes_.get(sessionId);
        return (attrs != null) ? attrs.get(name) : null;
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
        log.info("Name: " + name + " Value: " + value + " SessionId: " + id);
        String source = se.getSource().getClass().getName();
        String message = new StringBuffer("Attribute bound to session in ")
                .append(source).append("\nThe attribute name: ").append(name)
                .append("\n").append("The attribute value:").append(value)
                .append("\n").append("The session ID: ").append(id).toString();
        log.info(message);
        SetMappings(id, name, value);
        String D = GetMappings(id, "deviceId");
        String useR = GetMappings(id, "user");

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
        SetMappings_(id, name, value);
        String D_ = GetMappings_(id, "deviceId");
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
        String D = GetMappings(session.getId(), "deviceId");
        // sessionCreated fires BEFORE attributeAdded("deviceId"), so D is usually null here.
        // Always add the session to activeUsers; deviceId-based eviction runs in attributeAdded.
        if (D == null || !sessions.containsKey(D)) {
            activeUsers.put(session.getId(), session);
            log.info("sessionId added in event context: " + session.getId());
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
            // Clean up per-session attribute maps
            sessionAttributes.remove(id);
            sessionAttributes_.remove(id);
        }
    }
}
