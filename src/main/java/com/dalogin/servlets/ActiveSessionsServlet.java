package com.dalogin.servlets;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.jboss.logging.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Returns a JSON array of all active user sessions (user, deviceId, sessionId, creationTime).
 * <p>
 * Reads the {@code activeUsers} ConcurrentHashMap that is populated by
 * {@link com.dalogin.listeners.CustomHttpSessionListener} and stored in
 * the {@link ServletContext}.
 * <p>
 * Called by {@code simple-service-webapp /myresource/admin} via the Apache proxy.
 *
 * @author George Gaspar
 */
@WebServlet(urlPatterns = "/activeSessions", name = "ActiveSessionsServlet")
public class ActiveSessionsServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(ActiveSessionsServlet.class);

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String servletName = getServletName();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        log.debugf("HTTP request started: servlet=%s, method=%s, uri=%s", servletName, method, uri);
        try {

            response.setContentType("application/json");
            response.setCharacterEncoding("utf-8");

            ServletContext context = request.getServletContext();

            @SuppressWarnings("unchecked")
            ConcurrentHashMap<String, HttpSession> activeUsers =
                    (ConcurrentHashMap<String, HttpSession>) context.getAttribute("activeUsers");

            JSONArray sessionsArray = new JSONArray();

            if (activeUsers != null) {
                int index = 0;
                for (var entry : activeUsers.entrySet()) {
                    String sessionId = entry.getKey();
                    HttpSession session = entry.getValue();

                    String user = null;
                    String deviceId = null;
                    long creationTime = 0;

                    try {
                        Object userAttr = session.getAttribute("user");
                        Object deviceAttr = session.getAttribute("deviceId");
                        user = userAttr != null ? userAttr.toString() : null;
                        deviceId = deviceAttr != null ? deviceAttr.toString() : null;
                        creationTime = session.getCreationTime();
                    } catch (IllegalStateException e) {
                        // Session was invalidated between iteration and getAttribute — skip it
                        log.debug("Skipping invalidated session");
                        continue;
                    }

                    JSONObject sessionObj = new JSONObject();
                    sessionObj.put("id", index);
                    sessionObj.put("sessionId", sessionId);
                    sessionObj.put("user", user != null ? user : "");
                    sessionObj.put("deviceId", deviceId != null ? deviceId : "");
                    sessionObj.put("creationTime", creationTime);
                    sessionsArray.put(sessionObj);
                    index++;
                }
            }

            log.debugf("Active sessions count=%d", sessionsArray.length());

            response.setStatus(HttpServletResponse.SC_OK);
            try (PrintWriter out = response.getWriter()) {
                out.print(sessionsArray.toString());
                out.flush();
            }
        } finally {
            log.debugf("HTTP request completed: method=%s, uri=%s, status=%d", method, uri, response.getStatus());
        }
    }
}

