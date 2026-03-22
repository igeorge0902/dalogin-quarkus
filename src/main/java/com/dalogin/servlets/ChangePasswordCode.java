package com.dalogin.servlets;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2017
 */

import com.dalogin.SQLAccess;
import com.dalogin.utils.AesUtil;
import com.dalogin.utils.hmac512;
import com.dalogin.utils.sha512;
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
import java.util.List;

@WebServlet(urlPatterns = "/forgotPSwCode", name = "ChangePasswordCode")
public class ChangePasswordCode extends HttpServlet implements Serializable {
    private static final long serialVersionUID = -5814374401990509788L;
    private static final String SALT = "3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55";
    private static final String IV = "F27D5C9927726BCEFE7510B1BDD3D137";
    private static final String PASSPHRASE = "SecretPassphrase";
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
        ServletContext context = request.getServletContext();
        final long T2 = Long.parseLong(context.getAttribute("time").toString());

        try {
            String hmac = request.getHeader("X-HMAC-HASH").trim();
            String contentLength = request.getHeader("Content-Length");
            String time = request.getHeader("X-MICRO-TIME").trim();
            String email = request.getParameter("email");
            String confirmationCode = request.getParameter("cC");
            String deviceId = request.getParameter("deviceId").trim();
            String ios = request.getParameter("ios");
            String WebView = request.getHeader("User-Agent");
            String M = request.getHeader("M");
            if (M == null) {
                M = "";
            }
            String deviceId_ = request.getHeader("M-Device");
            Cookie[] cookies = request.getCookies();
            // retrieve email which requested the password reset
            List<String> cC = SQLAccess.getForgotPswConfirmationCode(email, context);
            String encrypted_token = aesUtil.encrypt(SALT, IV, cC.get(1), cC.get(0));
            // check if the original response cookie for the same client is present
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (cookie.getName().equalsIgnoreCase("XSRF-TOKEN")) {
                        if (cookie.getValue().equals(encrypted_token)) {
                            //do something
                        }
                    }
                }
            } else {
                throw new ServletException("There is no valid XSRF-TOKEN");
            }
            long T = Long.parseLong(time.trim());
            if (confirmationCode != null) {
                confirmationCode = confirmationCode.trim();
            } else {
                PrintWriter out = response.getWriter();
                JSONObject json = new JSONObject();
                json.put("Session", "raked");
                json.put("Success", "false");
                json.put("Error", "no confirmationCode!");
                out.print(json.toString());
                out.flush();
                return;
            }
            String hmacHash = hmac512.getCode_ForgetPSW_Hmac512(email, encrypted_token.substring(31, 34), deviceId, time, contentLength);
            log.info("HandShake was given: " + hmac + " & " + hmacHash);
            try {
                log.info("deviceId to be decrypted: " + deviceId_);
                deviceId = aesUtil.decrypt(SALT, IV, PASSPHRASE, deviceId_);
                log.info("deviceId decrypted: " + deviceId);
            } catch (Exception e) {
                log.info("There was no deviceId to be decrypted.");
            }

            if (hmac.equals(hmacHash) && confirmationCode.equals(sha512.string_hash(encrypted_token.substring(31, 34))) && ((T + T2) > System.currentTimeMillis())) {
                response.setContentType("application/json");
                response.setCharacterEncoding("utf-8");
                response.setStatus(200);
                PrintWriter out = response.getWriter();
                JSONObject json = new JSONObject();
                json.put("Success", "true");
                json.put("Code", "isValid");
                out.print(json.toString());
                out.flush();
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
        } catch (Exception e) {
            throw new ServletException(e.getCause().toString());
        }
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Set response content type
        response.setContentType("text/html");
        response.sendError(HttpServletResponse.SC_BAD_GATEWAY);
    }

    public void destroy() {
        // do nothing.
    }
}

