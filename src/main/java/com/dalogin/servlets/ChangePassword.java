package com.dalogin.servlets;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2017
 */

import com.dalogin.crypto.CryptoService;
import com.dalogin.persistence.passwordreset.PasswordResetManager;
import com.dalogin.servlets.requestrecord.ForgotPasswordRequest;
import com.dalogin.servlets.responsemap.PasswordResetResponses;
import com.dalogin.utils.SendHtmlEmail;
import com.dalogin.utils.hmac512;
import jakarta.inject.Inject;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.io.Serializable;

@WebServlet(urlPatterns = "/forgotPSw", name = "ChangePassword")
public class ChangePassword extends HttpServlet implements Serializable {
    private static final long serialVersionUID = 1920153247962686649L;
    private static final String SALT = "3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55";
    private static final String IV = "F27D5C9927726BCEFE7510B1BDD3D137";
    private static final String PASSPHRASE = "SecretPassphrase";
    private static final Logger log = Logger.getLogger(Logger.class.getName());

    @Inject
    CryptoService cryptoService;

    @Inject
    PasswordResetManager passwordResetManager;

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String servletName = getServletName();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        log.debugf("HTTP request started: servlet=%s, method=%s, uri=%s", servletName, method, uri);
        try {
        // Set response content type
        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");
        ServletContext context = request.getServletContext();
        final long T2 = Long.parseLong(context.getAttribute("time").toString());
        // Actual logic goes here.
        ForgotPasswordRequest req;
        String email;
        long T;
        try {
            req = ForgotPasswordRequest.from(request);
            T = Long.parseLong(req.microTime().trim());
            if (req.rawEmail() != null) {
                email = req.rawEmail().trim();
            } else {
                PasswordResetResponses.missingEmail(response);
                return;
            }
            String hmacHash = hmac512.getEmail_ForgetPSW_Hmac512(email, req.deviceId(), req.microTime(), req.contentLength());
            log.debug("Handshake validation executed for forgot password flow");
            String deviceId = decryptDeviceId(req.deviceId(), req.encryptedDeviceId());

            if (req.hmac().equals(hmacHash) && ((T + T2) > System.currentTimeMillis())) {
                handleForgotPassword(response, email, T, req.microTime());
            } else {
                PasswordResetResponses.validationFailed(response);
            }
        } catch (Exception e) {
            throw new ServletException(e.getCause() != null ? e.getCause().toString() : e.getMessage());
        }
        } finally {
            log.debugf("HTTP request completed: method=%s, uri=%s, status=%d", method, uri, response.getStatus());
        }
    }

    private String decryptDeviceId(String fallbackDeviceId, String encryptedDeviceId) {
        try {
            String decrypted = cryptoService.decrypt(SALT, IV, PASSPHRASE, encryptedDeviceId);
            log.debug("Encrypted device identifier was processed");
            return decrypted;
        } catch (Exception e) {
            log.debug("No encrypted device identifier provided for decryption");
            return fallbackDeviceId;
        }
    }

    private void handleForgotPassword(HttpServletResponse response, String email, long T, String time) throws Exception {
        String token = passwordResetManager.getForgotPswToken(email, T);
        if (token.equalsIgnoreCase("ilt")) {
            PasswordResetResponses.alreadyRequested(response);
        } else {
            String encryptedToken = cryptoService.encrypt(SALT, IV, time, token);
            // Construct requesting URL
            StringBuilder url = new StringBuilder();
            url.append(encryptedToken.substring(31, 34));
            SendHtmlEmail.generateAndSendEmail(email, url.toString());
            PasswordResetResponses.requestSucceeded(response, encryptedToken, encryptedToken.substring(31, 34));
        }
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String servletName = getServletName();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        log.debugf("HTTP request started: servlet=%s, method=%s, uri=%s", servletName, method, uri);
        // Set response content type
        try {
            response.setContentType("text/html");
            response.sendError(HttpServletResponse.SC_BAD_GATEWAY);
        } finally {
            log.debugf("HTTP request completed: method=%s, uri=%s, status=%d", method, uri, response.getStatus());
        }
    }
}
