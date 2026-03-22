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

    private static final Logger log = Logger.getLogger(Logger.class.getName());

    private AesUtil aesUtil;

    @Override
    public void init() throws ServletException {
        aesUtil = new AesUtil(KEYSIZE, ITERATIONCOUNT);
    }

    /**
     * Authentication via POST.
     */
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");

        // Invalidate old session if exists
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        ServletContext context = request.getServletContext();

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

        String hmac = rawHmac.trim();
        String contentLength = rawContentLength.trim();
        String time = rawTime.trim();
        String pass = rawPass.trim();
        String user = rawUser.trim();
        String deviceId = rawDeviceId.trim();
        String ios = request.getParameter("ios");
        String webView = request.getHeader("User-Agent");
        String M = request.getHeader("M");
        if (M == null) M = "";

        String deviceId_ = request.getHeader("M-Device");
        long T = Long.parseLong(time.trim());

        String hmacHash = hmac512.getLoginHmac512(user, pass, deviceId, time, contentLength);
        log.info("Handshake received: " + hmac + " vs expected: " + hmacHash);

        try {
            log.info("deviceId to be decrypted: " + deviceId_);
            deviceId = aesUtil.decrypt(SALT, IV, PASSPHRASE, deviceId_);
            log.info("deviceId decrypted: " + deviceId);
        } catch (Exception e) {
            log.info("No deviceId decryption performed.");
        }

        String hash1 = hashPassword(pass, user, context);

        // Validate password and HMAC
        if (pass.equals(hash1) && hmac.equals(hmacHash)) {
            createSession(request, context, response, user, deviceId, ios, webView, M);
        } else {
            sendAuthFailed(response);
        }
    }

    /**
     * Basic GET check, mainly validation.
     */
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("text/html");
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        try {
            String pass = request.getParameter("pswrd");
            String user = request.getParameter("user");
            String deviceId = request.getParameter("deviceId");

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

    private void createSession(HttpServletRequest request, ServletContext context, HttpServletResponse response,
                               String user, String deviceId, String ios, String webView, String M)
            throws ServletException, IOException {

        HttpSession session = request.getSession(true);
        long sessionCreated = session.getCreationTime();
        String sessionID = session.getId();

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
            List<String> token2 = SQLAccess.getToken2(deviceId, context);

            // Guard against race condition: if insertSessionCreated hasn't committed
            // yet, getToken2 may return an empty list. Retry once after a short delay.
            if (token2.size() < 2) {
                try { Thread.sleep(100); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
                token2 = SQLAccess.getToken2(deviceId, context);
            }
            if (token2.size() < 2) {
                log.error("getToken2 returned empty for deviceId=" + deviceId + " after retry");
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                JSONObject err = new JSONObject()
                        .put("Success", "false")
                        .put("Message", "Session token not yet available, please retry");
                writeJson(response, err);
                return;
            }

            String xsrfToken = aesUtil.encrypt(SALT, IV, token2.get(1), token2.get(0));

            String actualToken = xsrfToken.endsWith("=")
                    ? xsrfToken.substring(0, xsrfToken.length() - 1)
                    : xsrfToken.trim();

            // Cookies
            Cookie cookieXSRF = new Cookie("XSRF-TOKEN", actualToken);
            cookieXSRF.setSecure(true);
            cookieXSRF.setHttpOnly(true);
            cookieXSRF.setMaxAge(session.getMaxInactiveInterval());
            cookieXSRF.setPath(context.getContextPath());

            Cookie cookieToken = new Cookie("X-Token", token2.get(0));
            cookieToken.setSecure(true);
            cookieToken.setMaxAge(session.getMaxInactiveInterval());

            response.addCookie(cookieXSRF);
            response.addCookie(cookieToken);

            response.addHeader("X-Token", token2.get(0));
            response.setStatus(HttpServletResponse.SC_OK);

            session.setAttribute(cookieXSRF.getName(), cookieXSRF.getValue());
            session.setAttribute("TIME_", token2.get(1));

            JSONObject json = (ios != null)
                    ? buildMobileResponse(sessionID, token2)
                    : buildWebResponse(token2);

            writeJson(response, json);

        } catch (Exception e) {
            throw new ServletException(e.getCause() != null ? e.getCause().toString() : e.getMessage(), e);
        }
    }

    private JSONObject buildMobileResponse(String sessionID, List<String> token2) {
        return new JSONObject()
                .put("success", 1)
                .put("JSESSIONID", sessionID)
                .put("X-Token", token2.get(0));
    }

    private JSONObject buildWebResponse(List<String> token2) {
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
            return SQLAccess.getHash(pass, user, context);
        } catch (Exception e) {
            throw new ServletException(e.getMessage());
        }
    }
}
