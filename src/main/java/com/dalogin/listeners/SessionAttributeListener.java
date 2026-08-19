package com.dalogin.listeners;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2015
 */

import jakarta.servlet.annotation.WebListener;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionAttributeListener;
import jakarta.servlet.http.HttpSessionBindingEvent;
import org.jboss.logging.Logger;

@WebListener
public class SessionAttributeListener implements HttpSessionAttributeListener {

    private static final Logger log = Logger.getLogger(SessionAttributeListener.class.getName());

    /** Creates new SessionAttribListen */
    public SessionAttributeListener() {
        log.debugf("event=LISTENER_INIT listenerName=%s", getClass().getSimpleName());
    }

    public void attributeAdded(HttpSessionBindingEvent se) {
        HttpSession session = se.getSession();
        String id = session.getId();
        String name = se.getName();
        log.debugf("event=SESSION_ATTR_ADDED listenerName=%s sessionId=%s attributeName=%s attributeValue=%s",
                getClass().getSimpleName(), id, name, maskIfToken(name, se.getValue()));
    }

    public void attributeRemoved(HttpSessionBindingEvent se) {
        HttpSession session = se.getSession();
        String id = session.getId();
        String name = se.getName();
        if (name == null)
            name = "Unknown";
        log.debugf("event=SESSION_ATTR_REMOVED listenerName=%s sessionId=%s attributeName=%s",
                getClass().getSimpleName(), id, name);
    }

    public void attributeReplaced(HttpSessionBindingEvent se) {
        log.debugf("event=SESSION_ATTR_REPLACED listenerName=%s source=%s",
                getClass().getSimpleName(), se.getSource().getClass().getName());
    }

    private String maskIfToken(String attributeName, Object value) {
        if (value == null) {
            return "null";
        }
        String lower = attributeName == null ? "" : attributeName.toLowerCase();
        if (lower.contains("token") || lower.contains("ciphertext") || lower.contains("nonce") || lower.contains("xsrf")) {
            return "***";
        }
        return value.toString();
    }
}
