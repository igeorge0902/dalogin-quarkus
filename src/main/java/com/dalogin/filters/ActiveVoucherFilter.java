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
import org.apache.log4j.Logger;
import org.json.JSONObject;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;

@WebFilter(servletNames = {"GetAllPurchases", "CheckOut", "ManagePurchases"})
public class ActiveVoucherFilter implements Filter {
    private volatile static String Response = null;
    private volatile static String user = null;
    private volatile static List<String> token2;
    private volatile static String deviceId;
    private static Logger log = Logger.getLogger(Logger.class.getName());
    private ServletContext context;

    public void init(FilterConfig fConfig) throws ServletException {
        this.context = fConfig.getServletContext();
        this.context.log("AuthenticationFilter initialized");
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
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
        log.info("SessionId from request parameter: " + sessionId);
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
            user = (String) session.getAttribute("user");
            deviceId = (String) session.getAttribute("deviceId");
            try {
                Response = SQLAccess.checkActivation(user, context);
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
            }
            if (Response == "S") {
                try {
                    token2 = SQLAccess.getToken2(deviceId, context);
                } catch (Exception e) {
                    res.setContentType("application/json");
                    res.setCharacterEncoding("utf-8");
                    res.setStatus(502);
                    log.info(e.getMessage());
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
    }

    public void destroy() {
        //close any resources here
    }
}