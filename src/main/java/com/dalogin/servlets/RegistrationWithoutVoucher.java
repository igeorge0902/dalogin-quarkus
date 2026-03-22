package com.dalogin.servlets;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2015
 */

import com.dalogin.SQLAccess;
import com.dalogin.utils.AesUtil;
import com.dalogin.utils.EmailValidator;
import com.dalogin.utils.SendHtmlEmail;
import com.dalogin.utils.hmac512;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.*;
import org.apache.log4j.Logger;
import org.json.JSONObject;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Serializable;
import java.util.List;

@WebServlet(urlPatterns = "/registerWithoutVoucher", name = "RegistrationWithoutVoucher")
public class RegistrationWithoutVoucher extends HttpServlet implements Serializable {
    private static final long serialVersionUID = 7901395932118528100L;
    private static final String SALT = "3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55";
    private static final String IV = "F27D5C9927726BCEFE7510B1BDD3D137";
    private static final int KEYSIZE = 128;
    private static final int ITERATIONCOUNT = 1000;
    private static final Logger log = Logger.getLogger(Logger.class.getName());

    private AesUtil aesUtil;

    public void init() throws ServletException {
        aesUtil = new AesUtil(KEYSIZE, ITERATIONCOUNT);
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Set response content type
        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");
        // Actual logic goes here.
        String user = request.getParameter("user").trim();
        String pass = request.getParameter("pswrd").trim();
        String email = request.getParameter("email").trim();
        String deviceId = request.getParameter("deviceId").trim();
        String hmac = request.getHeader("X-HMAC-HASH");
        String contentLength = request.getHeader("Content-Length");
        String time = request.getHeader("X-MICRO-TIME");
        String ios = request.getParameter("ios");
        String WebView = request.getHeader("User-Agent");
        String M = request.getHeader("M");
        if (M == null) {
            M = "";
        }
        long T = Long.parseLong(time.trim());
        ServletContext context = request.getServletContext();
        final long T2 = Long.parseLong(context.getAttribute("time").toString());
        // Check core request parameters first
        if (email != null) email = email.trim();
        if (user.equals("") && user.trim().length() > 0 && EmailValidator.validate(email)) {
            String hmacHash = hmac512.getRegWithoutVoucherHmac512(user, email, pass, deviceId, time, contentLength);
            log.info("HandShake was given: " + hmac + " & " + hmacHash);
            HttpSession session = request.getSession(true);
            // synchronized session object to prevent concurrent update
            synchronized (session) {
                // Try - catch is necessary anyways, and will catch user names that have become identical in the meantime
                try {
                    if (hmac.equals(hmacHash) && ((T + T2) > System.currentTimeMillis())) {
                        String new_hash = SQLAccess.createUser(pass, user, email, context);
                        if ("I".equals(new_hash)) {
                            if (SQLAccess.insertDevice(deviceId, user, context)) {
                                session.setAttribute("user", user);
                                session.setAttribute("deviceId", deviceId);
                                //setting session to expire in 30 mins
                                session.setMaxInactiveInterval(30 * 60);
                                long SessionCreated = session.getCreationTime();
                                String sessionID = session.getId();
                                // insert sessionId for the device, then, if success, we can copy the token2
                                SQLAccess.insertSessionCreated(deviceId, SessionCreated, sessionID, context);
                                // Construct requesting URL
                                StringBuilder url = new StringBuilder();
                                // TODO: configuring email text for sending email about the registration
                                url.append("Thank you for regestering!");
                                SendHtmlEmail.generateAndSendEmail(email, url.toString());
                                // Build response based on client type
                                List<String> token2 = SQLAccess.getToken2(deviceId, context);
                                Cookie c = new Cookie("XSRF-TOKEN", aesUtil.encrypt(SALT, IV, time, token2.get(0)));
                                c.setSecure(true);
                                c.setMaxAge(session.getMaxInactiveInterval());
                                response.addCookie(c);
                                session.setAttribute(c.getName(), c.getValue());

                                if (ios != null) {
                                    // native mobile
                                    log.info("1");
                                    response.setContentType("application/json");
                                    response.setCharacterEncoding("utf-8");
                                    response.setStatus(200);
                                    PrintWriter out = response.getWriter();
                                    JSONObject json = new JSONObject();
                                    json.put("success", 1);
                                    json.put("JSESSIONID", sessionID);
                                    json.put("X-Token", token2);
                                    out.print(json.toString());
                                    out.flush();
                                } else if (WebView != null && WebView.contains("Mobile") && M.equals("M")) {
                                    // mobile webview
                                    log.info("2");
                                    response.addHeader("X-Token", token2.get(0));
                                    JSONObject json = new JSONObject();
                                    json.put("Session", "raked");
                                    json.put("Success", "true");
                                    json.put("JSESSIONID", sessionID);
                                    json.put("X-Token", token2);
                                    String homePage = getServletContext().getInitParameter("homePage");
                                    ServletContext otherContext = getServletContext().getContext(homePage);
                                    response.sendRedirect(otherContext.getContextPath() + "/tabularasa.html?JSESSIONID=" + sessionID);
                                } else {
                                    // standard path
                                    log.info("3");
                                    response.addHeader("X-Token", token2.get(0));
                                    PrintWriter out = response.getWriter();
                                    JSONObject json = new JSONObject();
                                    json.put("Session", "raked");
                                    json.put("Success", "true");
                                    json.put("X-Token", token2);
                                    out.print(json.toString());
                                    out.flush();
                                }
                            } else {
                                // insert_device fail
                                JSONObject json_ = new JSONObject();
                                json_.put("Error", "Registration failed");
                                response.setContentType("application/json");
                                response.setCharacterEncoding("utf-8");
                                response.setStatus(502);
                                try {
                                    // full delete
                                    SQLAccess.deleteUser(user, context);
                                } catch (Exception e1) {
                                    log.info("User delete(reset) FAILED!");
                                    throw new ServletException(e1.getCause().toString());
                                }
                                response.getWriter().write(json_.toString());
                                response.flushBuffer();
                            }
                        } else {
                            // unique constraint fail
                            response.setContentType("application/json");
                            response.setStatus(502);
                            PrintWriter out = response.getWriter();
                            out.print(new_hash);
                            out.flush();
                        }
                    } else {
                        // hmac error
                        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "hmac error");
                    }
                } catch (Exception e) {
                    // servlet runtime error
                    response.setContentType("application/json");
                    response.setStatus(502);
                    PrintWriter out = response.getWriter();
                    JSONObject json = new JSONObject();
                    json.put("Registration", "failed");
                    json.put("Email", "false");
                    json.put("Message", "I have gone to smoke a cigarette!");
                    out.print(json);
                    out.flush();
                }
            }
        } else {
            // email format failed
            response.setContentType("application/json");
            response.setStatus(502);
            PrintWriter out = response.getWriter();
            JSONObject json = new JSONObject();
            json.put("Registration", "failed");
            json.put("Email", "false");
            json.put("Message", "Not a valid email format!");
            out.print(json);
            out.flush();
        }
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Set response content type
        response.setContentType("text/html");
        try {
            String pass = request.getParameter("pswrd");
            String voucher = request.getParameter("voucher_");
            String deviceId = request.getParameter("deviceId");
            String user = request.getParameter("user");
            if (voucher.trim().isEmpty() || (user != null && user.trim().isEmpty()) || pass.trim().isEmpty() || deviceId.trim().isEmpty()) {
                response.sendError(HttpServletResponse.SC_BAD_GATEWAY, "Line 162");
            }
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_BAD_GATEWAY, "Line 166");
        }
    }

    public void destroy() {
        // do nothing.
    }
}
