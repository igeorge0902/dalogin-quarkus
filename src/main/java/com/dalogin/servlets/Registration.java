package com.dalogin.servlets;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2015
 */

import com.dalogin.crypto.CryptoService;
import com.dalogin.persistence.account.AccountManager;
import com.dalogin.persistence.devicesession.DeviceSessionManager;
import com.dalogin.persistence.devicesession.SessionTokens;
import com.dalogin.persistence.voucher.VoucherManager;
import com.dalogin.servlets.requestrecord.RegistrationRequest;
import com.dalogin.servlets.responsemap.RegistrationResponses;
import com.dalogin.servlets.responsemap.RegistrationSuccess;
import com.dalogin.utils.EmailValidator;
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

@WebServlet(urlPatterns = "/register", name = "Registration")
public class Registration extends HttpServlet implements Serializable {
    private static final long serialVersionUID = 4570645192274189831L;
    private static final String SALT = "3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55";
    private static final String IV = "F27D5C9927726BCEFE7510B1BDD3D137";
    private static final String activationToken = "G";
    private static final Logger log = Logger.getLogger(Logger.class.getName());

    @Inject
    CryptoService cryptoService;

    @Inject
    AccountManager accountManager;

    @Inject
    DeviceSessionManager deviceSessionManager;

    @Inject
    VoucherManager voucherManager;

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String servletName = getServletName();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        log.debugf("HTTP request started: servlet=%s, method=%s, uri=%s", servletName, method, uri);
        try {
        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");

        RegistrationRequest reg = RegistrationRequest.from(request);
        long T = Long.parseLong(reg.microTime());
        ServletContext context = request.getServletContext();
        final long T2 = Long.parseLong(context.getAttribute("time").toString());

        String voucher = reg.voucher();
        String user = reg.user();
        String email = reg.email();
        String pass = reg.password();
        String deviceId = reg.deviceId();

        // TODO: add password policy
        if (voucher != null && !voucher.equals("") && !user.equals("") && user.trim().length() > 0
                && EmailValidator.validate(email)) {
            String hmacHash = hmac512.getRegHmac512(user, email, pass, deviceId, voucher, reg.microTime(), reg.contentLength());
            log.info("HandShake was given: " + reg.hmac() + " & " + hmacHash);

            HttpSession session = request.getSession(true);

            // synchronized session object to prevent concurrent update
            synchronized (session) {
                session.setAttribute("voucher", voucher);

                // Try - catch is necessary anyways, and will catch user names that have become used in the meantime
                try {
                    if (voucherManager.registerVoucher(voucher) && reg.hmac().equals(hmacHash)
                            && ((T + T2) > System.currentTimeMillis())) {
                        String newHash = accountManager.createUser(pass, user, email);

                        if ("I".equals(newHash)) {
                            // setting session to expire in 30 mins
                            session.setMaxInactiveInterval(30 * 60);

                            long sessionCreated = session.getCreationTime();
                            String sessionId = session.getId();

                            // executes updates in chained method, where if any of them fails, the update will not be committed
                            if (accountManager.wrapUpRegistration(voucher, user, pass, deviceId, sessionCreated, sessionId)) {
                                // Publication happens only after the registration transaction committed.
                                session.setAttribute("user", user);
                                session.setAttribute("deviceId", deviceId);

                                // TODO: start it in a new thread
                                // SendHtmlEmail.generateAndSendEmail(email, url.toString());

                                buildRegistrationResponse(request, response, session, reg, deviceId, sessionId, context);
                            } else {
                                try {
                                    // full delete
                                    accountManager.deleteUser(user);
                                } catch (Exception e1) {
                                    log.info("User delete(reset) FAILED for voucher:" + voucher + "!");
                                    throw new ServletException(e1.getCause() != null ? e1.getCause().toString() : e1.getMessage());
                                }
                                RegistrationResponses.wrapUpFailed(response);
                                session.invalidate();
                                return;
                            }
                        } else {
                            voucherManager.resetVoucher(voucher, user);
                            RegistrationResponses.uniqueConstraintFailed(response, newHash);
                        }
                    } else {
                        // hmac error
                        RegistrationResponses.hmacError(response);
                    }
                } catch (Exception e) {
                    // servlet runtime error
                    try {
                        voucherManager.resetVoucher(voucher, user);
                        RegistrationResponses.runtimeFailure(response);
                    } catch (Exception e1) {
                        log.info("Voucher reset FAILED for vouchet:" + voucher + "!");
                        throw new ServletException(e1.getCause() != null ? e1.getCause().toString() : e1.getMessage());
                    }
                }
            }
        } else {
            // email format failed
            try {
                voucherManager.resetVoucher(voucher, user);
            } catch (Exception e1) {
                log.info("Voucher reset FAILED for vouchet:" + voucher + "!");
                throw new ServletException(e1.getCause() != null ? e1.getCause().toString() : e1.getMessage());
            }

            RegistrationResponses.emailValidationFailed(response);
        }
        } finally {
            log.debugf("HTTP request completed: method=%s, uri=%s, status=%d", method, uri, response.getStatus());
        }
    }

    private void buildRegistrationResponse(HttpServletRequest request, HttpServletResponse response,
                                            HttpSession session, RegistrationRequest reg, String deviceId,
                                            String sessionId, ServletContext context) throws IOException {
        SessionTokens tokens = toSessionTokens(deviceSessionManager.getToken2(deviceId));
        String xsrfToken = cryptoService.encrypt(SALT, IV, tokens.time(), tokens.token());

        String actualToken = xsrfToken.endsWith("=")
                ? xsrfToken.substring(0, xsrfToken.length() - 1)
                : xsrfToken;

        session.setAttribute("XSRF-TOKEN", actualToken);

        RegistrationSuccess success = new RegistrationSuccess(
                context.getContextPath(), session.getMaxInactiveInterval(), sessionId, tokens.token(), actualToken);

        if (reg.mobileClient()) {
            log.info("1");
            RegistrationResponses.nativeMobileSucceeded(response, success);
        } else if (reg.mobileWebview()) {
            log.info("2");
            RegistrationResponses.mobileWebviewSucceeded(response, success, context.getContextPath());
        } else {
            log.info("3");
            RegistrationResponses.standardSucceeded(response, success);
        }
    }

    private SessionTokens toSessionTokens(java.util.List<String> token2) {
        return new SessionTokens(token2.get(0), token2.get(1));
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String servletName = getServletName();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        log.debugf("HTTP request started: servlet=%s, method=%s, uri=%s", servletName, method, uri);
        try {
            response.setContentType("text/html");

            try {
                String voucher = request.getParameter("voucher");
                String pass = request.getParameter("pswrd");
                voucher = request.getParameter("voucher_");
                String deviceId = request.getParameter("deviceId");
                String user = request.getParameter("user");

                if (voucher.trim().isEmpty()
                        || (user != null && user.trim().isEmpty())
                        || pass.trim().isEmpty()
                        || deviceId.trim().isEmpty()) {
                    response.sendError(HttpServletResponse.SC_BAD_GATEWAY, "Line 361");
                }
            } catch (Exception e) {
                response.sendError(HttpServletResponse.SC_BAD_GATEWAY, "Line 365");
            }
        } finally {
            log.debugf("HTTP request completed: method=%s, uri=%s, status=%d", method, uri, response.getStatus());
        }
    }
}
