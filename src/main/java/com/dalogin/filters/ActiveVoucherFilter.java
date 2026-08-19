package com.dalogin.filters;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2015
 */

import com.dalogin.SQLAccess;
import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.jboss.logging.Logger;
import org.json.JSONObject;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;

@WebFilter(servletNames = {"GetAllPurchases", "CheckOut", "ManagePurchases"})
public class ActiveVoucherFilter implements Filter {
    private static final Logger log = Logger.getLogger(ActiveVoucherFilter.class);
    private ServletContext context;

    public void init(FilterConfig fConfig) throws ServletException {
        this.context = fConfig.getServletContext();
        log.debug("ActiveVoucherFilter initialized");
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String method = req.getMethod();
        String uri = req.getRequestURI();
        log.debugf("HTTP request started: filter=%s, method=%s, uri=%s", "ActiveVoucherFilter", method, uri);
        try {
        HttpSession session = req.getSession(false);
        HashMap<String, String> error = new HashMap<>();
        // Set the response message's MIME type
        response.setContentType("text/html;charset=UTF-8");
        Cookie[] cookies = req.getCookies();
        // Get JSESSION url parameter. Later it needs to be sent as header
        String sessionId = req.getParameter("JSESSIONID");
        if (session != null && sessionId == null) {
            sessionId = session.getId();
        }
        log.debug("Session identifier resolved for active voucher flow");
        if (cookies == null || !req.isRequestedSessionIdValid() || session == null) {
            res.setContentType("application/json");
            res.setCharacterEncoding("utf-8");
            res.setStatus(502);
            PrintWriter out = response.getWriter();
            //create Json Object
            JSONObject json = new JSONObject();
            // put some value pairs into the JSON object .
            error.put("acticeUsers", "failed");
            error.put("Success", "false");
            error.put("Error Message:", "no valid session");
            json.put("Error Details", error);
            // finally output the json string
            out.print(json.toString());
            out.flush();
        } else if (session != null && req.isRequestedSessionIdValid() && cookies != null) {
            // Get user from session
            String user = (String) session.getAttribute("user");
            String deviceId = (String) session.getAttribute("deviceId");
            String activationResponse;
            try {
                activationResponse = SQLAccess.checkActivation(user, context);
            } catch (Exception e) {
                res.setContentType("application/json");
                res.setCharacterEncoding("utf-8");
                res.setStatus(502);
                PrintWriter out = response.getWriter();
                //create Json Object
                JSONObject json = new JSONObject();
                // put some value pairs into the JSON object .
                error.put("SQLAccess", "failed");
                error.put("Success", "false");
                // finally output the json string
                out.print(json.toString());
                out.flush();
                return;
            }
            if ("S".equals(activationResponse)) {
                List<String> token2;
                try {
                    token2 = SQLAccess.getToken2(deviceId, context);
                } catch (Exception e) {
                    res.setContentType("application/json");
                    res.setCharacterEncoding("utf-8");
                    res.setStatus(502);
                    log.error("Error retrieving token2", e);
                    return;
                }
                res.setContentType("application/json");
                res.setCharacterEncoding("utf-8");
                res.setHeader("Response", "S");
                res.setStatus(300);
                res.addHeader("X-Token", token2.get(0));
                PrintWriter out = response.getWriter();
                //create Json Object
                JSONObject json = new JSONObject();
                // put some value pairs into the JSON object .
                error.put("Activation", "false");
                error.put("Success", "false");
                error.put("User", user);
                error.put("deviceId", deviceId);
                json.put("Error Details", error);
                // finally output the json string
                out.print(json.toString());
                out.flush();
            } else {
                // pass the request along the filter chain
                chain.doFilter(request, response);
            }
        }
        } finally {
            log.debugf("HTTP request completed: method=%s, uri=%s, status=%d", method, uri, res.getStatus());
        }
    }

    public void destroy() {
        //close any resources here
    }
}
