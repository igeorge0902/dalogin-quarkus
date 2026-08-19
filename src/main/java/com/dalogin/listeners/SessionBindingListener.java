package com.dalogin.listeners;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpSessionBindingEvent;
import jakarta.servlet.http.HttpSessionBindingListener;
import org.jboss.logging.Logger;

public class SessionBindingListener implements HttpSessionBindingListener {
    private static final Logger LOG = Logger.getLogger(SessionBindingListener.class);
    ServletContext context;

    /**
     * @param context
     */
    public SessionBindingListener(ServletContext context) {
        this.context = context;
    }

    /**
     *
     */
    public void valueBound(HttpSessionBindingEvent event) {
        LOG.debugf("event=SESSION_BINDING_VALUE_BOUND listenerName=%s attributeName=%s attributeValue=%s",
                SessionBindingListener.class.getSimpleName(), event.getName(), maskIfToken(event.getName(), event.getValue()));
    }

    /**
     *
     */
    public void valueUnbound(HttpSessionBindingEvent event) {
        LOG.debugf("event=SESSION_BINDING_VALUE_UNBOUND listenerName=%s attributeName=%s attributeValue=%s",
                SessionBindingListener.class.getSimpleName(), event.getName(), maskIfToken(event.getName(), event.getValue()));
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
