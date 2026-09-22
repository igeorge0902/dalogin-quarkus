package com.dalogin.servlets;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2017
 */

import com.dalogin.persistence.devicesession.DeviceSessionManager;
import com.dalogin.servlets.responsemap.LogoutResponses;
import jakarta.inject.Inject;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.jboss.logging.Logger;

import java.io.IOException;

@WebServlet(urlPatterns = "/logout", name = "LoggingOut")
public class LoggingOut extends HttpServlet {
    private static final long serialVersionUID = -9006384818191092461L;
    private static final Logger log = Logger.getLogger(LoggingOut.class);

    @Inject
    DeviceSessionManager deviceSessionManager;

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String servletName = getServletName();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        log.debugf("HTTP request started: servlet=%s, method=%s, uri=%s", servletName, method, uri);
        try {
            doGet(request, response);
        } finally {
            log.debugf("HTTP request completed: method=%s, uri=%s, status=%d", method, uri, response.getStatus());
        }
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String servletName = getServletName();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        log.debugf("HTTP request started: servlet=%s, method=%s, uri=%s", servletName, method, uri);
        try {
            HttpSession session = request.getSession(false);
            if (session != null) {
                ServletContext context = request.getServletContext();
                session.removeAttribute("user");
                try {
                    deviceSessionManager.logout(session.getId());
                } catch (Exception e) {
                    throw new ServletException(e.getMessage());
                }
                session.invalidate();
                LogoutResponses.loggedOut(response);
                return;
            }
            LogoutResponses.alreadyLoggedOut(response);
        } finally {
            log.debugf("HTTP request completed: method=%s, uri=%s, status=%d", method, uri, response.getStatus());
        }
    }
}
