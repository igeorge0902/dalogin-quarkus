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
        log.info(getClass().getName());
    }

    public void attributeAdded(HttpSessionBindingEvent se) {
        HttpSession session = se.getSession();
        String id = session.getId();
        String name = se.getName();
        String value = String.valueOf(se.getValue());
        String source = se.getSource().getClass().getName();
        String message = new StringBuilder("Attribute bound to session in ")
                .append(source).append("\nThe attribute name: ").append(name)
                .append("\n").append("The attribute value:").append(value)
                .append("\n").append("The session ID: ").append(id).toString();
        log.info(message);
    }

    public void attributeRemoved(HttpSessionBindingEvent se) {
        HttpSession session = se.getSession();
        String id = session.getId();
        String name = se.getName();
        if (name == null)
            name = "Unknown";
        String value = String.valueOf(se.getValue());
        String source = se.getSource().getClass().getName();
        String message = new StringBuilder("Attribute unbound from session in ")
                .append(source).append("\nThe attribute name: ").append(name)
                .append("\n").append("The attribute value: ").append(value)
                .append("\n").append("The session ID: ").append(id).toString();
        log.info(message);
    }

    public void attributeReplaced(HttpSessionBindingEvent se) {
        String source = se.getSource().getClass().getName();
        String message = new StringBuilder("Attribute replaced in session  ")
                .append(source).toString();
        log.info(message);
    }
}
