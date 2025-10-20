package com.dalogin.servlets;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2017
 */
//Import required java libraries

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

/**
 *
 */
@WebServlet(urlPatterns = "/forgotPSwCode", name = "ChangePasswordCode")
public class ChangePasswordCode extends HttpServlet implements Serializable {
    /**
     *
     */
    private static final long serialVersionUID = -5814374401990509788L;
    /**
     * A final string as SALT to be used for AES encryption / decryption that is typically required to be random or pseudorandom.
     * The fix value is to demonstrate how the AES works across multiple platforms (AngularJS, iOS Swift) with the same input arguments.
     */
    private static final String SALT = "3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55";
    /**
     * A final string as IV to be used for AES encryption / decryption that is typically required to be random or pseudorandom.
     * The fix value is to demonstrate how the AES works across multiple platforms (AngularJS, iOS Swift) with the same input arguments.
     */
    private static final String IV = "F27D5C9927726BCEFE7510B1BDD3D137";
    /**
     * A final string as PASSPHRASE to be used for AES encryption / decryption that is typically required to be random or pseudorandom.
     * The fix value is to demonstrate how the AES works across multiple platforms (AngularJS, iOS Swift) with the same input arguments.
     */
    private static final String PASSPHRASE = "SecretPassphrase";
    /**
     * A final int as KEYSIZE to be used for AES encryption / decryption that is typically required to be random or pseudorandom.
     * The fix value is to demonstrate how the AES works across multiple platforms (AngularJS, iOS Swift) with the same input arguments.
     */
    private static final int KEYSIZE = 128;
    /**
     * A final int as ITERATIONCOUNT to be used for AES encryption / decryption that is typically required to be random or pseudorandom.
     * The fix value is to demonstrate how the AES works across multiple platforms (AngularJS, iOS Swift) with the same input arguments.
     */
    private static final int ITERATIONCOUNT = 1000;
    /**
     * User email received from the request as parameter.
     */
    private volatile static String email;
    /**
     * ConfirmationCode which the user received in the email.
     */
    private volatile static String confirmationCode;
    /**
     * forgotRequestToken retrieved from the dB by the email address, which requested the password reset.
     */
    private volatile static String encrypted_token;
    /**
     * User deviceId received from the request as parameter.
     */
    private volatile static String deviceId;
    /**
     * User deviceId received from the request as parameter if it was initiated from the native mobile app.
     */
    private volatile static String deviceId_;
    /**
     * The content length of the request.
     */
    private volatile static String contentLength;
    /**
     * A flag indicating if the request is coming from the native mobile app.
     */
    private volatile static String ios;
    /**
     * A flag indicating if the request is coming from mobile web.
     */
    private volatile static String WebView;
    /**
     * A flag, which is set for every request coming from the mobile app by its UrlProtocol.
     */
    private volatile static String M;
    /**
     * A List<String> including the forgotRequestToken and forgotRequestTime for the email, which requested the password reset.
     */
    private volatile static List<String> cC;
    /**
     * The X-HMAC-HASH hash value received from the request as parameter.
     */
    private volatile static String hmac;
    /**
     * The hmac hash value, which will be matched against the received one (X-HMAC-HASH).
     */
    private volatile static String hmacHash;
    /**
     * The timestamp of the request: the difference, measured in milliseconds, between the current time and midnight, January 1, 1970 UTC.
     */
    private volatile static String time;
    /**
     *  A class for AES encryption and decryption.
     */
    private static AesUtil aesUtil;
    /**
     * An array initialized to contain the request cookies.
     */
    private static volatile Cookie[] cookies;
    /**
     * The context parameter defining the opening hours.
     */
    private static volatile long T;
    /**
     * A static logger for the class.
     */
    private static Logger log = Logger.getLogger(Logger.class.getName());

    /**
     * This method is called in the early life-cycle of the servlet, i.e. before everything.
     */
    public void init() throws ServletException {
        aesUtil = new AesUtil(KEYSIZE, ITERATIONCOUNT);
    }

    /**
     * This method is called when the servlet receives a POST request from the client. 
     */
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
            confirmationCode = request.getParameter("cC");
            deviceId = request.getParameter("deviceId").trim();
            ios = request.getParameter("ios");
            WebView = request.getHeader("User-Agent");
            M = request.getHeader("M");
            if (M == null) {
                M = "";
            }
            deviceId_ = request.getHeader("M-Device");
            cookies = request.getCookies();
            // retrieve email which requested the password reset
            cC = SQLAccess.getForgotPswConfirmationCode(email, context);
            encrypted_token = aesUtil.encrypt(SALT, IV, cC.get(1), cC.get(0));
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
            T = Long.parseLong(time.trim());
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
            }
            hmacHash = hmac512.getCode_ForgetPSW_Hmac512(email, encrypted_token.substring(31, 34), deviceId, time, contentLength);
            log.info("HandShake was given: " + hmac + " & " + hmacHash);
            try {
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
         * confirmationCode is matched against the forgotRequestToken for the email, which requested the password reset
         * without direct authentication! We rely on the owner of the email address.
         */
        if (hmac.equals(hmacHash) && confirmationCode.equals(sha512.string_hash(encrypted_token.substring(31, 34))) && ((T + T2) > System.currentTimeMillis())) {
            // X-Token should be sent as json response I guess
            // native mobile
            if (ios != null) {
                try {
                    log.info("1");
                    response.setContentType("application/json");
                    response.setCharacterEncoding("utf-8");
                    response.setStatus(200);
                    PrintWriter out = response.getWriter();
                    JSONObject json = new JSONObject();
                    json.put("Success", "true");
                    json.put("Code", "isValid");
                    out.print(json.toString());
                    out.flush();
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
                    PrintWriter out = response.getWriter();
                    JSONObject json = new JSONObject();
                    json.put("Success", "true");
                    json.put("Code", "isValid");
                    out.print(json.toString());
                    out.flush();
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
                    PrintWriter out = response.getWriter();
                    JSONObject json = new JSONObject();
                    json.put("Success", "true");
                    json.put("Code", "isValid");
                    out.print(json.toString());
                    out.flush();
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

    /**
     * This method is called when the servlet receives a GET request from the client. 
     */
    public synchronized void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Set response content type
        response.setContentType("text/html");
        response.sendError(HttpServletResponse.SC_BAD_GATEWAY);
    }

    public void destroy() {
        // do nothing.
    }
}