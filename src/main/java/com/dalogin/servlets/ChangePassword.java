package com.dalogin.servlets;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2017
 */
//Import required java libraries

import com.dalogin.SQLAccess;
import com.dalogin.utils.AesUtil;
import com.dalogin.utils.SendHtmlEmail;
import com.dalogin.utils.hmac512;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.json.JSONObject;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Serializable;

/**
 *
 *
 */
@WebServlet(urlPatterns = "/forgotPSw", name = "ChangePassword")
public class ChangePassword extends HttpServlet implements Serializable {
    /**
     *
     */
    private static final long serialVersionUID = 1920153247962686649L;
    private static final String SALT = "3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55";
    private static final String IV = "F27D5C9927726BCEFE7510B1BDD3D137";
    private static final String PASSPHRASE = "SecretPassphrase";
    private static final int KEYSIZE = 128;
    private static final int ITERATIONCOUNT = 1000;
    /**
     * User email received from the request as parameter.
     */
    private volatile static String email;
    /**
     * User password value retrieved from the dB.
     */
    private volatile static String deviceId;
    private volatile static String deviceId_;
    private volatile static String contentLength;
    private volatile static String ios;
    private volatile static String WebView;
    private volatile static String M;
    private volatile static String token;
    private volatile static String hmac;
    private volatile static String hmacHash;
    private volatile static String time;
    private static AesUtil aesUtil;
    private static volatile Cookie c;
    private static volatile long T;
    private static Logger log = Logger.getLogger(Logger.class.getName());

    public void init() throws ServletException {
        aesUtil = new AesUtil(KEYSIZE, ITERATIONCOUNT);
    }

    public synchronized void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Set response content type
        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");
        ServletContext context = request.getServletContext();
        final long T2 = Long.parseLong(context.getAttribute("time").toString());
        // Actual logic goes here.		
        try {
            // hmac is not encrypted, just the password inside
            hmac = request.getHeader("X-HMAC-HASH").trim();
            contentLength = request.getHeader("Content-Length");
            time = request.getHeader("X-MICRO-TIME").trim();
            email = request.getParameter("email");
            deviceId = request.getParameter("deviceId").trim();
            ios = request.getParameter("ios");
            WebView = request.getHeader("User-Agent");
            M = request.getHeader("M");
            if (M == null) {
                M = "";
            }
            deviceId_ = request.getHeader("M-Device");
            T = Long.parseLong(time.trim());
            if (email != null) {
                email = email.trim();
            } else {
                PrintWriter out = response.getWriter();
                JSONObject json = new JSONObject();
                json.put("Session", "raked");
                json.put("Success", "false");
                json.put("Error", "no email!");
                out.print(json.toString());
                out.flush();
            }
            hmacHash = hmac512.getEmail_ForgetPSW_Hmac512(email, deviceId, time, contentLength);
            log.info("HandShake was given: " + hmac + " & " + hmacHash);
            try {
                //TODO: make use of M-Device
                log.info("deviceId to be decrypted: " + deviceId_);
                deviceId = aesUtil.decrypt(SALT, IV, PASSPHRASE, deviceId_);
                log.info("deviceId decrypted: " + deviceId);
            } catch (Exception e) {
                log.info("There was no deviceId to be decrypted.");
            }
        } catch (Exception e) {
            throw new ServletException(e.getCause().toString());
        }
        /**
         * check if the email which requests the password reset is the one that actually requested it
         */
        if (hmac.equals(hmacHash) && ((T + T2) > System.currentTimeMillis())) {
            // X-Token should be sent as json response I guess
            // native mobile
            if (ios != null) {
                try {
                    log.info("1");
                    response.setContentType("application/json");
                    response.setCharacterEncoding("utf-8");
                    response.setStatus(200);
                    token = SQLAccess.getForgotPswToken(email, T, context);
                    if (token.equalsIgnoreCase("ilt")) {
                        PrintWriter out = response.getWriter();
                        JSONObject json = new JSONObject();
                        json.put("Session", "raked");
                        json.put("Success", "false");
                        out.print(json.toString());
                        out.flush();
                    } else {
                        String encrypted_token = aesUtil.encrypt(SALT, IV, time, token);
                        // Construct requesting URL
                        StringBuilder url = new StringBuilder();
                        url.append(encrypted_token.substring(31, 34));
                        SendHtmlEmail.generateAndSendEmail(email, url.toString());
                        c = new Cookie("XSRF-TOKEN", encrypted_token);
                        c.setSecure(true);
                        c.setMaxAge(1800);
                        response.addCookie(c);
                        PrintWriter out = response.getWriter();
                        JSONObject json = new JSONObject();
                        json.put("Success", "true");
                        json.put("Code", encrypted_token.substring(31, 34));
                        out.print(json.toString());
                        out.flush();
                    }
                } catch (Exception e) {
                    throw new ServletException(e.getCause().toString());
                }
                // mobile webView
            } else if (WebView.contains("Mobile") && M.equals("M")) {
                try {
                    log.info("2");
                    response.setContentType("application/json");
                    response.setCharacterEncoding("utf-8");
                    response.setStatus(200);
                    token = SQLAccess.getForgotPswToken(email, T, context);
                    if (token.equalsIgnoreCase("ilt")) {
                        PrintWriter out = response.getWriter();
                        JSONObject json = new JSONObject();
                        json.put("Success", "false");
                        out.print(json.toString());
                        out.flush();
                    } else {
                        String encrypted_token = aesUtil.encrypt(SALT, IV, time, token);
                        // Construct requesting URL
                        StringBuilder url = new StringBuilder();
                        url.append(encrypted_token.substring(31, 34));
                        SendHtmlEmail.generateAndSendEmail(email, url.toString());
                        c = new Cookie("XSRF-TOKEN", encrypted_token);
                        c.setSecure(true);
                        c.setMaxAge(1800);
                        response.addCookie(c);
                        PrintWriter out = response.getWriter();
                        JSONObject json = new JSONObject();
                        json.put("Success", "true");
                        json.put("Code", encrypted_token.substring(31, 34));
                        out.print(json.toString());
                        out.flush();
                    }
                } catch (Exception e) {
                    throw new ServletException(e.getCause().toString());
                }
            }
            // standard path
            else {
                try {
                    log.info("3");
                    response.setContentType("application/json");
                    response.setCharacterEncoding("utf-8");
                    response.setStatus(200);
                    token = SQLAccess.getForgotPswToken(email, T, context);
                    if (token.equalsIgnoreCase("ilt")) {
                        PrintWriter out = response.getWriter();
                        JSONObject json = new JSONObject();
                        json.put("Success", "false");
                        out.print(json.toString());
                        out.flush();
                    } else {
                        String encrypted_token = aesUtil.encrypt(SALT, IV, time, token);
                        // Construct requesting URL
                        StringBuilder url = new StringBuilder();
                        url.append(encrypted_token.substring(31, 34));
                        SendHtmlEmail.generateAndSendEmail(email, url.toString());
                        c = new Cookie("XSRF-TOKEN", encrypted_token);
                        c.setSecure(true);
                        c.setMaxAge(1800);
                        response.addCookie(c);
                        PrintWriter out = response.getWriter();
                        JSONObject json = new JSONObject();
                        json.put("Success", "true");
                        json.put("Code", encrypted_token.substring(31, 34));
                        out.print(json.toString());
                        out.flush();
                    }
                } catch (Exception e) {
                    throw new ServletException(e.getCause().toString());
                }
            }
        } else {
            response.setContentType("application/json");
            response.setCharacterEncoding("utf-8");
            response.setStatus(502);
            PrintWriter out = response.getWriter();
            JSONObject json = new JSONObject();
            json.put("Success", "false");
            out.print(json.toString());
            out.flush();
        }
    }

    public synchronized void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Set response content type
        response.setContentType("text/html");
        response.sendError(HttpServletResponse.SC_BAD_GATEWAY);
    }

    public void destroy() {
        // do nothing.
    }
}