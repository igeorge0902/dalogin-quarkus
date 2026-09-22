package com.dalogin.servlets;

/**
 * @author George
 * @year 2015
 */

import com.dalogin.crypto.CryptoService;
import com.dalogin.persistence.PersistenceOperationException;
import com.dalogin.persistence.account.AccountManager;
import com.dalogin.persistence.devicesession.DeviceSessionManager;
import com.dalogin.persistence.devicesession.SessionTokens;
import com.dalogin.servlets.requestrecord.LoginRequest;
import com.dalogin.servlets.responsemap.LoginResponses;
import com.dalogin.servlets.responsemap.LoginSuccess;
import com.dalogin.utils.hmac512;
import jakarta.inject.Inject;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.io.Serializable;

@WebServlet(urlPatterns = "/HelloWorld", name = "HelloWorld")
public class HelloWorld extends HttpServlet implements Serializable {

    private static final long serialVersionUID = 6378614133674149101L;

    // Crypto constants
    private static final String SALT = "3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55";
    private static final String IV = "F27D5C9927726BCEFE7510B1BDD3D137";
    private static final String PASSPHRASE = "SecretPassphrase";

    private static final Logger log = Logger.getLogger(Logger.class.getName());

    @Inject
    CryptoService cryptoService;

    @Inject
    AccountManager accountManager;

    @Inject
    DeviceSessionManager deviceSessionManager;

    /**
     * Authentication via POST.
     */
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String servletName = getServletName();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        log.debugf("HTTP request started: servlet=%s, method=%s, uri=%s", servletName, method, uri);
        try {
            response.setContentType("application/json");
            response.setCharacterEncoding("utf-8");

            // Invalidate old session if exists
            HttpSession oldSession = request.getSession(false);
            if (oldSession != null) {
                oldSession.invalidate();
            }

            LoginRequest login = LoginRequest.from(request);
            if (!login.hasRequiredValues()) {
                LoginResponses.missingRequiredInput(response);
                return;
            }

            // Preserve the current numeric validation. The value itself is not otherwise used.
            login.validatedMicroTime();

            String hmacHash = hmac512.getLoginHmac512(
                    login.user(), login.password(), login.deviceId(), login.microTime(), login.contentLength());
            log.debug("Handshake validation executed for login flow");

            String deviceId = decryptDeviceId(login.deviceId(), login.encryptedDeviceId());
            String passwordHash = accountManager.getHash(login.password(), login.user());

            if (!login.password().equals(passwordHash) || !login.hmac().equals(hmacHash)) {
                LoginResponses.authenticationFailed(response);
                return;
            }

            createSession(request, response, login.user(), deviceId, login.mobileClient());
        } finally {
            log.debugf("HTTP request completed: method=%s, uri=%s, status=%d", method, uri, response.getStatus());
        }
    }

    /**
     * Basic GET check, mainly validation.
     */
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String servletName = getServletName();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        log.debugf("HTTP request started: servlet=%s, method=%s, uri=%s", servletName, method, uri);

        try {
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

    /**
     * Creates a pending session (needed for its ID/creation time), atomically establishes the
     * device/session/token rows, and only then publishes session attributes and writes the
     * response. A persistence failure rolls back the transaction and invalidates the pending
     * session instead of retrying.
     */
    private void createSession(HttpServletRequest request, HttpServletResponse response,
                                String user, String deviceId, boolean mobileClient) throws IOException {
        HttpSession session = request.getSession(true);
        session.setMaxInactiveInterval(30 * 60);

        SessionTokens tokens;
        try {
            tokens = deviceSessionManager.establishLogin(deviceId, user, session.getCreationTime(), session.getId());
        } catch (PersistenceOperationException e) {
            session.invalidate();
            log.errorf(e, "Session persistence failed for deviceId=%s", deviceId);
            LoginResponses.sessionPersistenceFailed(response);
            return;
        }

        String xsrfToken;
        try {
            xsrfToken = cryptoService.encrypt(SALT, IV, tokens.time(), tokens.token());
        } catch (Exception e) {
            session.invalidate();
            throw new IOException("Failed to prepare the login response", e);
        }

        String actualToken = xsrfToken.endsWith("=")
                ? xsrfToken.substring(0, xsrfToken.length() - 1)
                : xsrfToken.trim();

        // Publication happens only after the database transaction and token preparation succeeded.
        synchronized (session) {
            session.setAttribute("user", user);
            session.setAttribute("deviceId", deviceId);
            session.removeAttribute("pswrd");
            session.setAttribute("XSRF-TOKEN", actualToken);
            session.setAttribute("TIME_", tokens.time());
        }

        LoginResponses.loginSucceeded(response, new LoginSuccess(
                request.getServletContext().getContextPath(),
                session.getMaxInactiveInterval(),
                session.getId(),
                tokens.token(),
                actualToken,
                mobileClient
        ));
    }
}
