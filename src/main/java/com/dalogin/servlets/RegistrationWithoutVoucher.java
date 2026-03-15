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
    /**
     *
     */
    private static final long serialVersionUID = 7901395932118528100L;
    /**
     *
     */
    private static final String SALT = "3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55";
    private static final String IV = "F27D5C9927726BCEFE7510B1BDD3D137";
    private static final int KEYSIZE = 128;
    private static final int ITERATIONCOUNT = 1000;
    /**
     *
     */
    private static Logger log = Logger.getLogger(Logger.class.getName());
    /**
     *
     */
    private volatile static String pass;
    /**
     *
     */
    private volatile static String user;
    /**
     *
     */
    private volatile static String voucher;
    /**
     *
     */
    private volatile static String deviceId;
    /**
     *
     */
    private volatile static String contentLength;
    /**
     *
     */
    private volatile static HttpSession session;
    /**
     *
     */
    private volatile static long SessionCreated;
    /**
     *
     */
    private volatile static String sessionID;
    /**
     *
     */
    private volatile static String email;
    /**
     *
     */
    private volatile static String ios;
    /**
     *
     */
    private volatile static String WebView;
    /**
     *
     */
    private volatile static String M;
    /**
     *
     */
    private volatile static List<String> token2;
    /**
     *
     */
    private volatile static String hmac;
    /**
     *
     */
    private volatile static String hmacHash;
    /**
     *
     */
    private volatile static String time;
    /**
     *
     */
    private static AesUtil aesUtil;
    private static volatile Cookie c;
    private static volatile long T;
    private static volatile String new_hash;

    public void init() throws ServletException {
        aesUtil = new AesUtil(KEYSIZE, ITERATIONCOUNT);
    }

    /**
     *
     * @param request
     * @param response
     * @throws ServletException
     * @throws IOException
     */
    public synchronized void processRequest(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    }

    public synchronized void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Set response content type
        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");
        // Actual logic goes here.
        user = request.getParameter("user").trim();
        pass = request.getParameter("pswrd").trim();
        email = request.getParameter("email").trim();
        deviceId = request.getParameter("deviceId").trim();
        hmac = request.getHeader("X-HMAC-HASH");
        contentLength = request.getHeader("Content-Length");
        time = request.getHeader("X-MICRO-TIME");
        ios = request.getParameter("ios");
        WebView = request.getHeader("User-Agent");
        M = request.getHeader("M");
        if (M == null) {
            M = "";
        }
        T = Long.parseLong(time.trim());
        ServletContext context = request.getServletContext();
        final long T2 = Long.parseLong(context.getAttribute("time").toString());
        // Check core request parameters first
        if (email != null) email = email.trim();
        if (user.equals("") && user.trim().length() > 0 && EmailValidator.validate(email)) {
            hmacHash = hmac512.getRegWithoutVoucherHmac512(user, email, pass, deviceId, time, contentLength);
            log.info("HandShake was given: " + hmac + " & " + hmacHash);
            session = request.getSession(true);
            // synchronized session object to prevent concurrent update
            synchronized (session) {
                // Try - catch is necessary anyways, and will catch user names that have become identical in the meantime
                try {
                    if (hmac.equals(hmacHash) && ((T + T2) > System.currentTimeMillis())) {
                        if ((new_hash_(pass, user, email, context) == "I")) {
                            if (SQLAccess.insertDevice(deviceId, user, context)) {
                                session.setAttribute("user", user);
                                session.setAttribute("deviceId", deviceId);
                                //setting session to expire in 30 mins
                                session.setMaxInactiveInterval(30 * 60);
                                SessionCreated = session.getCreationTime();
                                sessionID = session.getId();
                                // insert sessionId for the device, then, if success, we can copy the token2
                                SQLAccess.insertSessionCreated(deviceId, SessionCreated, sessionID, context);
                                // Construct requesting URL
                                StringBuilder url = new StringBuilder();
                                // TODO: configuring email text for sending email about the registration
                                url.append("Thank you for regestering!");
                                //remove, if not needed.
                                SendHtmlEmail.generateAndSendEmail(email, url.toString());
                                String homePage = getServletContext().getInitParameter("homePage");
                                ServletContext otherContext = getServletContext().getContext(homePage);
                                // native mobile
                                if (ios != null) {
                                    try {
                                        log.info("1");
                                        token2 = SQLAccess.getToken2(deviceId, context);
                                        c = new Cookie("XSRF-TOKEN", aesUtil.encrypt(SALT, IV, time, token2.get(0)));
                                        c.setSecure(true);
                                        c.setMaxAge(session.getMaxInactiveInterval());
                                        response.addCookie(c);
                                        response.setContentType("application/json");
                                        response.setCharacterEncoding("utf-8");
                                        response.setStatus(200);
                                        session.setAttribute(c.getName(), c.getValue());
                                        PrintWriter out = response.getWriter();
                                        JSONObject json = new JSONObject();
                                        json.put("success", 1);
                                        json.put("JSESSIONID", sessionID);
                                        json.put("X-Token", token2);
                                        out.print(json.toString());
                                        out.flush();
                                    } catch (Exception e) {
                                        throw new ServletException(e.getCause().toString());
                                    }
                                    // mobile webview
                                } else if (WebView.contains("Mobile") && M.equals("M")) {
                                    try {
                                        log.info("2");
                                        token2 = SQLAccess.getToken2(deviceId, context);
                                        c = new Cookie("XSRF-TOKEN", aesUtil.encrypt(SALT, IV, time, token2.get(0)));
                                        c.setSecure(true);
                                        c.setMaxAge(session.getMaxInactiveInterval());
                                        response.addCookie(c);
                                        // The token2 will be used as key-salt-whatever as originally planned.
                                        response.addHeader("X-Token", token2.get(0));
                                        session.setAttribute(c.getName(), c.getValue());
                                        JSONObject json = new JSONObject();
                                        json.put("Session", "raked");
                                        json.put("Success", "true");
                                        json.put("JSESSIONID", sessionID);
                                        // this is necessary because the X-Token header did not appear in the native mobile app
                                        json.put("X-Token", token2);
                                        response.sendRedirect(otherContext.getContextPath() + "/tabularasa.html?JSESSIONID=" + sessionID);
                                    } catch (Exception e) {
                                        throw new ServletException(e.getCause().toString());
                                    }
                                }
                                // standard path
                                else {
                                    try {
                                        log.info("3");
                                        token2 = SQLAccess.getToken2(deviceId, context);
                                        c = new Cookie("XSRF-TOKEN", aesUtil.encrypt(SALT, IV, time, token2.get(0)));
                                        c.setSecure(true);
                                        c.setMaxAge(session.getMaxInactiveInterval());
                                        response.addCookie(c);
                                        // The token2 will be used as key-salt-whatever as originally planned.
                                        response.addHeader("X-Token", token2.get(0));
                                        // TODO: finish cross-site request forgery protection
                                        session.setAttribute(c.getName(), c.getValue());
                                        PrintWriter out = response.getWriter();
                                        JSONObject json = new JSONObject();
                                        json.put("Session", "raked");
                                        json.put("Success", "true");
                                        // this is necessary because the X-Token header did not appear in the native mobile app
                                        json.put("X-Token", token2);
                                        out.print(json.toString());
                                        out.flush();
                                    } catch (Exception e) {
                                        throw new ServletException(e.getCause().toString());
                                    }
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
                                    log.info("User delete(reset) FAILED for voucher:" + voucher + "!");
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
                            SQLAccess.resetVoucher(voucher, user, context);
                            out.print(new_hash);
                            out.flush();
                        }
                    } else {
                        // hmac error
                        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "hmac error");
                    }
                } catch (Exception e) {
                    // servlet runtime error
                    try {
                        SQLAccess.resetVoucher(voucher, user, context);
                        response.setContentType("application/json");
                        response.setStatus(502);
                        PrintWriter out = response.getWriter();
                        JSONObject json = new JSONObject();
                        json.put("Registration", "failed");
                        json.put("Email", "false");
                        json.put("Message", "I have gone to smoke a cigarette!");
                        out.print(json);
                        out.flush();
                    } catch (Exception e1) {
                        log.info("Voucher reset FAILED for vouchet:" + voucher + "!");
                        throw new ServletException(e1.getCause().toString());
                    }
                }
            }
        } else {
            // email format failed
            try {
                SQLAccess.resetVoucher(voucher, user, context);
            } catch (Exception e1) {
                log.info("Voucher reset FAILED for vouchet:" + voucher + "!");
                throw new ServletException(e1.getCause().toString());
            }
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

    public synchronized void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        processRequest(request, response);
        // Set response content type
        response.setContentType("text/html");
        try {
            voucher = request.getParameter("voucher");
            pass = request.getParameter("pswrd");
            voucher = request.getParameter("voucher_");
            deviceId = request.getParameter("deviceId");
            if (voucher.trim().isEmpty() || user.trim().isEmpty() || pass.trim().isEmpty() || deviceId.trim().isEmpty()) {
                response.sendError(HttpServletResponse.SC_BAD_GATEWAY, "Line 162");
            }
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_BAD_GATEWAY, "Line 166");
        }
    }

    public void destroy() {
        // do nothing.
    }

    /**
     *
     * @param pass
     * @param user
     * @param email
     * @param context
     * @return
     * @throws Exception
     */
    private String new_hash_(String pass, String user, String email, ServletContext context) throws Exception {
        new_hash = SQLAccess.createUser(pass, user, email, context);
        return new_hash;
    }
}
