package com.dalogin.servlets;

/**
 * @author George
 * @year 2015
 */

import com.dalogin.SQLAccess;
import com.dalogin.utils.AesUtil;
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

@WebServlet(urlPatterns = "/HelloWorld", name = "HelloWorld")
public class HelloWorld extends HttpServlet implements Serializable {

    private static final long serialVersionUID = 6378614133674149101L;

    // Crypto constants
    private static final String SALT = "3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55";
    private static final String IV = "F27D5C9927726BCEFE7510B1BDD3D137";
    private static final String PASSPHRASE = "SecretPassphrase";
    private static final int KEYSIZE = 128;
    private static final int ITERATIONCOUNT = 1000;

    // Session/user-related state
    private volatile static String pass;
    private volatile static String user;
    private volatile static String hash1;
    private volatile static String deviceId;
    private volatile static String deviceId_;
    private volatile static String contentLength;
    private volatile static String ios;
    private volatile static String webView;
    private volatile static String M;
    private volatile static HttpSession session;
    private volatile static long sessionCreated;
    private volatile static String sessionID;
    private volatile static List<String> token2;
    private volatile static String hmac;
    private volatile static String hmacHash;
    private volatile static String time;
    private static volatile long T;

    // Tokens
    private static volatile String actualToken;
    private static volatile String xsrfToken;

    // Cookies
    private static volatile Cookie cookieXSRF;
    private static volatile Cookie cookieToken;

    // Utilities
    private static AesUtil aesUtil;
    private static final Logger log = Logger.getLogger(Logger.class.getName());

    @Override
    public void init() throws ServletException {
        aesUtil = new AesUtil(KEYSIZE, ITERATIONCOUNT);
    }

    /**
     * Authentication via POST.
     */
    @Override
    public synchronized void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");

        // Invalidate old session if exists
        session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        ServletContext context = request.getServletContext();
      //  final long T2 = Long.parseLong(context.getAttribute("time").toString());

        // Extract headers/parameters
        String rawHmac = request.getHeader("X-HMAC-HASH");
        String rawContentLength = request.getHeader("Content-Length");
        String rawTime = request.getHeader("X-MICRO-TIME");
        String rawPass = request.getParameter("pswrd");
        String rawUser = request.getParameter("user");
        String rawDeviceId = request.getParameter("deviceId");

        if (rawHmac == null || rawContentLength == null || rawTime == null
                || rawPass == null || rawUser == null || rawDeviceId == null) {
            response.setStatus(502);
            JSONObject err = new JSONObject();
            err.put("Success", "false");
            err.put("Message", "Missing required headers or parameters");
            writeJson(response, err);
            return;
        }

        hmac = rawHmac.trim();
        contentLength = rawContentLength.trim();
        time = rawTime.trim();
        pass = rawPass.trim();
        user = rawUser.trim();
        deviceId = rawDeviceId.trim();
        ios = request.getParameter("ios");
        webView = request.getHeader("User-Agent");
        M = request.getHeader("M");
        if (M == null) M = "";

        deviceId_ = request.getHeader("M-Device");
        T = Long.parseLong(time.trim());

        hmacHash = hmac512.getLoginHmac512(user, pass, deviceId, time, contentLength);
        log.info("Handshake received: " + hmac + " vs expected: " + hmacHash);

        try {
            log.info("deviceId to be decrypted: " + deviceId_);
            deviceId = aesUtil.decrypt(SALT, IV, PASSPHRASE, deviceId_);
            log.info("deviceId decrypted: " + deviceId);
        } catch (Exception e) {
            log.info("No deviceId decryption performed.");
        }

        hash1 = hashPassword(pass, user, context);

        // Validate password and HMAC
        if (pass.equals(hash1) && hmac.equals(hmacHash)) {
            createSession(request, context, response);
        } else {
            sendAuthFailed(response);
        }
    }

    /**
     * Basic GET check, mainly validation.
     */
    @Override
    public synchronized void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("text/html");
        session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        try {
            pass = request.getParameter("pswrd");
            user = request.getParameter("user");
            deviceId = request.getParameter("deviceId");

            if (user.trim().isEmpty() || pass.trim().isEmpty() || deviceId.trim().isEmpty()) {
                response.sendError(HttpServletResponse.SC_BAD_GATEWAY);
            }
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_BAD_GATEWAY);
        }
    }

    @Override
    public void destroy() {
    }

    private void createSession(HttpServletRequest request, ServletContext context, HttpServletResponse response)
            throws ServletException, IOException {

        session = request.getSession(true);
        sessionCreated = session.getCreationTime();
        sessionID = session.getId();

        synchronized (session) {
            session.setAttribute("user", user);
            session.setAttribute("deviceId", deviceId);
            session.removeAttribute("pswrd");
        }

        try {
            SQLAccess.insertDevice(deviceId, user, context);
            SQLAccess.insertSessionCreated(deviceId, sessionCreated, sessionID, context);
        } catch (Exception e) {
            throw new ServletException(e.getCause() != null ? e.getCause().toString() : e.getMessage(), e);
        }

        session.setMaxInactiveInterval(30 * 60);

        try {
            token2 = SQLAccess.getToken2(deviceId, context);
            xsrfToken = aesUtil.encrypt(SALT, IV, token2.get(1), token2.get(0));

            actualToken = xsrfToken.endsWith("=")
                    ? xsrfToken.substring(0, xsrfToken.length() - 1)
                    : xsrfToken.trim();

            // Cookies
            cookieXSRF = new Cookie("XSRF-TOKEN", actualToken);
            cookieXSRF.setSecure(true);
            cookieXSRF.setHttpOnly(true);
            cookieXSRF.setMaxAge(session.getMaxInactiveInterval());
            cookieXSRF.setPath(context.getContextPath());

            cookieToken = new Cookie("X-Token", token2.get(0));
            cookieToken.setSecure(true);
            cookieToken.setMaxAge(session.getMaxInactiveInterval());

            response.addCookie(cookieXSRF);
            response.addCookie(cookieToken);

            response.addHeader("X-Token", token2.get(0));
            response.setStatus(HttpServletResponse.SC_OK);

            session.setAttribute(cookieXSRF.getName(), cookieXSRF.getValue());
            session.setAttribute("TIME_", token2.get(1));

            JSONObject json = (ios != null)
                    ? buildMobileResponse()
                    : buildWebResponse();

            writeJson(response, json);

        } catch (Exception e) {
            throw new ServletException(e.getCause() != null ? e.getCause().toString() : e.getMessage(), e);
        }
    }

    private JSONObject buildMobileResponse() {
        return new JSONObject()
                .put("success", 1)
                .put("JSESSIONID", sessionID)
                .put("X-Token", token2.get(0));
    }

    private JSONObject buildWebResponse() {
        return new JSONObject()
                .put("Session", "raked")
                .put("Success", "true")
                .put("X-Token", token2.get(0));
    }

    private void sendAuthFailed(HttpServletResponse response) throws IOException {
        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");
        response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);

        JSONObject json = new JSONObject()
                .put("Session creation", "failed")
                .put("Success", "false");

        writeJson(response, json);
    }

    private void writeJson(HttpServletResponse response, JSONObject json) throws IOException {
        try (PrintWriter out = response.getWriter()) {
            out.print(json.toString());
            out.flush();
        }
    }

    private String hashPassword(String pass, String user, ServletContext context) throws ServletException {
        try {
            hash1 = SQLAccess.getHash(pass, user, context);
        } catch (Exception e) {
            throw new ServletException(e.getMessage());
        }
        return hash1;
    }
}
