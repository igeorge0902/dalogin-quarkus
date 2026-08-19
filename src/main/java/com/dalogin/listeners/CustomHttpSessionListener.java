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
import org.jboss.logging.Logger;

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
    private static final Logger log = Logger.getLogger(CustomHttpSessionListener.class);

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
        log.debugf("event=SESSION_ATTR_MAP_UPDATED listenerName=%s sessionId=%s attributeName=%s attributeValue=%s",
                CustomHttpSessionListener.class.getSimpleName(), sessionId, name, maskIfToken(name, value));
    }

    private String GetMappings(String sessionId, String name) {
        Map<String, String> attrs = sessionAttributes.get(sessionId);
        return (attrs != null) ? attrs.get(name) : null;
    }

    private void SetMappings_(String sessionId, String name, String value) {
        Map<String, String> attrs = getSessionMap_(sessionId);
        attrs.put(name, value);
        log.debugf("event=SESSION_ATTR_MAP_UPDATED listenerName=%s sessionId=%s attributeName=%s attributeValue=%s",
                CustomHttpSessionListener.class.getSimpleName(), sessionId, name, maskIfToken(name, value));
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
            log.debugf("event=SESSION_ATTR_SKIPPED listenerName=%s sessionId=%s attributeName=%s type=%s",
                    CustomHttpSessionListener.class.getSimpleName(), se.getSession().getId(), se.getName(),
                    se.getValue().getClass().getName());
            return;
        }
        HttpSession session = se.getSession();
        ServletContext context = session.getServletContext();
        ConcurrentHashMap<String, HttpSession> activeUsers = (ConcurrentHashMap<String, HttpSession>) context.getAttribute("activeUsers");
        SetMultimap<String, String> sessions = (SetMultimap<String, String>) context.getAttribute("sessions");
        String id = session.getId();
        String name = se.getName();
        String value = (String) se.getValue();
        log.debugf("event=SESSION_ATTR_ADDED listenerName=%s sessionId=%s attributeName=%s attributeValue=%s",
                CustomHttpSessionListener.class.getSimpleName(), id, name, maskIfToken(name, value));
        SetMappings(id, name, value);
        String D = GetMappings(id, "deviceId");
        String useR = GetMappings(id, "user");

        // ── Enforce one session per deviceId ──────────────────────────
        // When the "deviceId" attribute is set, evict any previous session
        // that was bound to the same device.
        if ("deviceId".equals(name) && D != null) {
            Set<String> oldEntries = sessions.get(D);
            if (!oldEntries.isEmpty()) {
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
                        log.debugf("event=SESSION_EVICTED listenerName=%s oldSessionId=%s",
                                CustomHttpSessionListener.class.getSimpleName(), oldSid);
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
            log.debug("Unable to add session mapping", e);
        }
        activeUsers.put(session.getId(), session);
        log.debugf("event=SESSION_STATE_UPDATED listenerName=%s activeUserCount=%d",
                CustomHttpSessionListener.class.getSimpleName(), activeUsers.size());
    }

    @Override
    public void attributeRemoved(HttpSessionBindingEvent se) {
        // Quarkus CDI may store internal objects as session attributes;
        // skip processing for non-String values to avoid ClassCastException.
        if (!(se.getValue() instanceof String)) {
            log.debugf("event=SESSION_ATTR_REMOVAL_SKIPPED listenerName=%s sessionId=%s attributeName=%s type=%s",
                    CustomHttpSessionListener.class.getSimpleName(), se.getSession().getId(), se.getName(),
                    se.getValue().getClass().getName());
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
        log.debugf("event=SESSION_ATTR_REMOVED listenerName=%s sessionId=%s attributeName=%s attributeValue=%s",
                CustomHttpSessionListener.class.getSimpleName(), id, name, maskIfToken(name, value));
        SetMappings_(id, name, value);
        String D_ = GetMappings_(id, "deviceId");
        // removes existing sessionId
        activeUsers.remove(id);
        log.debugf("event=SESSION_ID_REMOVED listenerName=%s sessionId=%s", CustomHttpSessionListener.class.getSimpleName(), id);
        try {
            // removes deviceId from helper list (sessions Multimap is a helper list, but is able to list the active users )
            sessions.removeAll(D_);
        } catch (Exception e) {
            // error handling for empty leafs
            log.debug("No device left to remove from sessions map");
        }
        log.debugf("event=SESSION_STATE_UPDATED listenerName=%s activeUserCount=%d",
                CustomHttpSessionListener.class.getSimpleName(), activeUsers.size());
    }

    @Override
    public void attributeReplaced(HttpSessionBindingEvent arg0) {
    }

    @SuppressWarnings("unchecked")
    public void sessionCreated(HttpSessionEvent event) {
        HttpSession session = event.getSession();
        ServletContext context = session.getServletContext();
        log.debugf("event=SESSION_CREATED listenerName=%s sessionId=%s", CustomHttpSessionListener.class.getSimpleName(), session.getId());
        ConcurrentHashMap<String, HttpSession> activeUsers = (ConcurrentHashMap<String, HttpSession>) context.getAttribute("activeUsers");
        SetMultimap<String, String> sessions = (SetMultimap<String, String>) context.getAttribute("sessions");
        String D = GetMappings(session.getId(), "deviceId");
        // sessionCreated fires BEFORE attributeAdded("deviceId"), so D is usually null here.
        // Always add the session to activeUsers; deviceId-based eviction runs in attributeAdded.
        if (D == null || !sessions.containsKey(D)) {
            activeUsers.put(session.getId(), session);
            log.debugf("event=SESSION_REGISTERED listenerName=%s sessionId=%s", CustomHttpSessionListener.class.getSimpleName(), session.getId());
        }
        log.debugf("event=SESSION_STATE_UPDATED listenerName=%s activeUserCount=%d",
                CustomHttpSessionListener.class.getSimpleName(), activeUsers.size());
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
            log.debugf("event=SESSION_DESTROYED listenerName=%s sessionId=%s", CustomHttpSessionListener.class.getSimpleName(), id);
            activeUsers.remove(session.getId());
            sessions.removeAll(D_);
            // runs logging out to make the user look like logged_out
            try {
                SQLAccess.logout(session.getId(), context);
            } catch (Exception e) {
                // error handling for empty leafs
                log.debug("No device left to remove during logout cleanup");
            }
                log.debugf("event=SESSION_STATE_UPDATED listenerName=%s activeUserCount=%d",
                        CustomHttpSessionListener.class.getSimpleName(), activeUsers.size());
            // Clean up per-session attribute maps
            sessionAttributes.remove(id);
            sessionAttributes_.remove(id);
        }
    }

    private String maskIfToken(String attributeName, String value) {
        if (value == null) {
            return "null";
        }
        String lower = attributeName == null ? "" : attributeName.toLowerCase();
        if (lower.contains("token") || lower.contains("ciphertext") || lower.contains("nonce") || lower.contains("xsrf")) {
            return "***";
        }
        return value;
    }
}
