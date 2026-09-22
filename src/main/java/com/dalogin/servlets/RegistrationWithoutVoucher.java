package com.dalogin.servlets;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2015
 */

import com.dalogin.crypto.CryptoService;
import com.dalogin.persistence.PersistenceOperationException;
import com.dalogin.persistence.account.AccountManager;
import com.dalogin.persistence.devicesession.DeviceSessionManager;
import com.dalogin.persistence.devicesession.SessionTokens;
import com.dalogin.servlets.requestrecord.RegistrationWithoutVoucherRequest;
import com.dalogin.servlets.responsemap.RegistrationWithoutVoucherResponses;
import com.dalogin.servlets.responsemap.RegistrationWithoutVoucherSuccess;
import com.dalogin.utils.EmailValidator;
import com.dalogin.utils.SendHtmlEmail;
import com.dalogin.utils.hmac512;
import jakarta.inject.Inject;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.io.Serializable;
import java.util.List;

@WebServlet(urlPatterns = "/registerWithoutVoucher", name = "RegistrationWithoutVoucher")
public class RegistrationWithoutVoucher extends HttpServlet implements Serializable {
    private static final long serialVersionUID = 7901395932118528100L;
    private static final String SALT = "3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55";
    private static final String IV = "F27D5C9927726BCEFE7510B1BDD3D137";
    private static final Logger log = Logger.getLogger(Logger.class.getName());

    @Inject
    CryptoService cryptoService;

    @Inject
    AccountManager accountManager;

    @Inject
    DeviceSessionManager deviceSessionManager;

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String servletName = getServletName();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        log.debugf("HTTP request started: servlet=%s, method=%s, uri=%s", servletName, method, uri);
        try {
        // Set response content type
        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");
        // Actual logic goes here.
        RegistrationWithoutVoucherRequest reg = RegistrationWithoutVoucherRequest.from(request);
        long T = Long.parseLong(reg.microTime().trim());
        ServletContext context = request.getServletContext();
        final long T2 = Long.parseLong(context.getAttribute("time").toString());
        String user = reg.user();
        String email = reg.email();
        String pass = reg.password();
        String deviceId = reg.deviceId();
        // Preserved verbatim: this condition can never be true because it requires an empty user
        // AND a non-empty trimmed user at the same time. Existing baseline behavior, not corrected.
        if (user.equals("") && user.trim().length() > 0 && EmailValidator.validate(email)) {
            String hmacHash = hmac512.getRegWithoutVoucherHmac512(user, email, pass, deviceId, reg.microTime(), reg.contentLength());
            log.info("HandShake was given: " + reg.hmac() + " & " + hmacHash);
            HttpSession session = request.getSession(true);
            // synchronized session object to prevent concurrent update
            synchronized (session) {
                // Try - catch is necessary anyways, and will catch user names that have become identical in the meantime
                try {
                    if (reg.hmac().equals(hmacHash) && ((T + T2) > System.currentTimeMillis())) {
                        String newHash = accountManager.createUser(pass, user, email);
                        if ("I".equals(newHash)) {
                            // setting session to expire in 30 mins
                            session.setMaxInactiveInterval(30 * 60);
                            long sessionCreated = session.getCreationTime();
                            String sessionId = session.getId();

                            SessionTokens tokens;
                            try {
                                tokens = deviceSessionManager.establishLogin(deviceId, user, sessionCreated, sessionId);
                            } catch (PersistenceOperationException e) {
                                try {
                                    accountManager.deleteUser(user);
                                } catch (Exception e1) {
                                    log.info("User delete(reset) FAILED!");
                                    throw new ServletException(e1.getCause() != null ? e1.getCause().toString() : e1.getMessage());
                                }
                                session.invalidate();
                                RegistrationWithoutVoucherResponses.insertDeviceFailed(response);
                                return;
                            }

                            // Publication happens only after the establishLogin transaction committed.
                            session.setAttribute("user", user);
                            session.setAttribute("deviceId", deviceId);

                            // TODO: configuring email text for sending email about the registration
                            SendHtmlEmail.generateAndSendEmail(email, "Thank you for regestering!");

                            List<String> token2 = List.of(tokens.token(), tokens.time());
                            String xsrfToken = cryptoService.encrypt(SALT, IV, reg.microTime(), token2.get(0));

                            session.setAttribute("XSRF-TOKEN", xsrfToken);

                            RegistrationWithoutVoucherSuccess success = new RegistrationWithoutVoucherSuccess(
                                    session.getMaxInactiveInterval(), sessionId, token2, xsrfToken);

                            if (reg.mobileClient()) {
                                log.info("1");
                                RegistrationWithoutVoucherResponses.nativeMobileSucceeded(response, success);
                            } else if (reg.mobileWebview()) {
                                log.info("2");
                                String homePage = getServletContext().getInitParameter("homePage");
                                ServletContext otherContext = getServletContext().getContext(homePage);
                                RegistrationWithoutVoucherResponses.mobileWebviewSucceeded(response, success, otherContext.getContextPath());
                            } else {
                                log.info("3");
                                RegistrationWithoutVoucherResponses.standardSucceeded(response, success);
                            }
                        } else {
                            // unique constraint fail
                            RegistrationWithoutVoucherResponses.uniqueConstraintFailed(response, newHash);
                        }
                    } else {
                        // hmac error
                        RegistrationWithoutVoucherResponses.hmacError(response);
                    }
                } catch (Exception e) {
                    // servlet runtime error
                    RegistrationWithoutVoucherResponses.runtimeFailure(response);
                }
            }
        } else {
            // email format failed
            RegistrationWithoutVoucherResponses.emailValidationFailed(response);
        }
        } finally {
            log.debugf("HTTP request completed: method=%s, uri=%s, status=%d", method, uri, response.getStatus());
        }
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String servletName = getServletName();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        log.debugf("HTTP request started: servlet=%s, method=%s, uri=%s", servletName, method, uri);
        try {
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
        } finally {
            log.debugf("HTTP request completed: method=%s, uri=%s, status=%d", method, uri, response.getStatus());
        }
    }
}
