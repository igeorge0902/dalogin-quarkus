package com.dalogin.servlets;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2017
 */

import com.dalogin.crypto.CryptoService;
import com.dalogin.persistence.account.AccountManager;
import com.dalogin.persistence.passwordreset.PasswordResetManager;
import com.dalogin.servlets.requestrecord.NewPasswordRequest;
import com.dalogin.servlets.responsemap.PasswordResetResponses;
import com.dalogin.utils.hmac512;
import com.dalogin.utils.sha512;
import jakarta.inject.Inject;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.io.Serializable;
import java.util.List;

@WebServlet(urlPatterns = "/forgotPSwNewPSw", name = "ChangePasswordNewPassword")
public class ChangePasswordNewPassword extends HttpServlet implements Serializable {
    private static final long serialVersionUID = -5814374401990509788L;
    private static final String SALT = "3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55";
    private static final String IV = "F27D5C9927726BCEFE7510B1BDD3D137";
    private static final String PASSPHRASE = "SecretPassphrase";
    private static final Logger log = Logger.getLogger(Logger.class.getName());

    @Inject
    CryptoService cryptoService;

    @Inject
    PasswordResetManager passwordResetManager;

    @Inject
    AccountManager accountManager;

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

        NewPasswordRequest req;
        String encryptedToken;
        String stringHash;
        String hmacHash;
        long T;
        String confirmationCode;

        try {
            req = NewPasswordRequest.from(request);
            confirmationCode = req.confirmationCode();
            Cookie[] cookies = request.getCookies();
            // retrieve email which requested the password reset
            List<String> cC = passwordResetManager.getForgotPswConfirmationCode(req.email());
            encryptedToken = cryptoService.encrypt(SALT, IV, cC.get(1), cC.get(0));
            if (req.password().length() < 1) {
                PasswordResetResponses.passwordTooShort(response);
                return;
            }
            T = Long.parseLong(req.microTime().trim());
            if (confirmationCode != null) {
                confirmationCode = confirmationCode.trim();
            } else {
                PasswordResetResponses.missingConfirmationCode(response);
                return;
            }
            stringHash = sha512.string_hash(encryptedToken.substring(31, 34));
            hmacHash = hmac512.getPass_ForgetPSW_Hmac512(req.email(), req.password(), stringHash, req.deviceId(), req.microTime(), req.contentLength());
            log.debug("Handshake validation executed for forgot password new password flow");
            String deviceId = decryptDeviceId(req.deviceId(), req.encryptedDeviceId());
        } catch (Exception e) {
            throw new ServletException("The " + request.getParameter("cC") + " is not a valid code!");
        }

        if (req.hmac().equals(hmacHash) && confirmationCode.equals(stringHash) && ((T + T2) > System.currentTimeMillis())) {
            try {
                accountManager.changePassword(req.password(), req.email());
            } catch (Exception e1) {
                throw new ServletException(e1.getCause() != null ? e1.getCause().toString() : e1.getMessage());
            }
            PasswordResetResponses.codeValid(response);
        } else {
            PasswordResetResponses.validationFailed(response);
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
