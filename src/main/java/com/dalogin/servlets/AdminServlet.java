package com.dalogin.servlets;

import com.dalogin.SystemConstants;
import com.dalogin.client.ServiceClient;
import com.dalogin.persistence.account.AccountManager;
import com.dalogin.persistence.devicesession.DeviceSessionManager;
import com.dalogin.servlets.responsemap.AdminResponses;
import jakarta.inject.Inject;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@WebServlet(urlPatterns = {"/admin", "/admin/newsSettings/screen"}, name = "AdminServlet")
public class AdminServlet extends HttpServlet {
    private static final long serialVersionUID = 5570497466931245289L;
    private static final Logger log = Logger.getLogger(AdminServlet.class);
    private static final String NEWS_SCREEN_PATH = "/admin/newsSettings/screen";

    @Inject
    AccountManager accountManager;

    @Inject
    DeviceSessionManager deviceSessionManager;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        if (isNewsSettingsRequest(request)) {
            response.setHeader("Allow", "GET, PUT");
            AdminResponses.error(response, 405, "Method not allowed");
            return;
        }
        processRequest(request, response);
    }

    private boolean isNewsSettingsRequest(HttpServletRequest request) {
        return NEWS_SCREEN_PATH.equals(request.getServletPath()) && request.getPathInfo() == null;
    }

    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        if (isNewsSettingsRequest(request)) {
            processRequest(request, response);
            return;
        }
        super.doPut(request, response);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        processRequest(request, response);
    }

    private void processRequest(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String servletName = getServletName();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        log.debugf("HTTP request started: servlet=%s, method=%s, uri=%s", servletName, method, uri);
        try {
        response.setContentType("text/html;charset=UTF-8");
        HttpSession session = request.getSession(false);
        String sessionId = Optional.ofNullable(request.getParameter("JSESSIONID")).orElseGet(() -> session != null ? session.getId() : null);
        log.debug("Session identifier resolved for admin flow");

            try {
                performTask(request, response, session);
            } catch (Exception e) {
                log.error("Error during task execution", e);
                AdminResponses.error(response, 502, "Internal server error");
            }
        } finally {
            log.debugf("HTTP request completed: method=%s, uri=%s, status=%d", method, uri, response.getStatus());
        }
    }

    private void performTask(HttpServletRequest request, HttpServletResponse response, HttpSession session) throws Exception {
        if (session == null) {
            AdminResponses.error(response, 502, "Session is invalid");
            return;
        }

        String deviceId = (String) session.getAttribute("deviceId");
        String user = (String) session.getAttribute("user");

        if (deviceId == null || user == null) {
            AdminResponses.error(response, 502, "Missing deviceId or user in session");
            return;
        }

        String token = deviceSessionManager.getToken(deviceId);
        String activationResponse = accountManager.checkActivation(user);

        if ("S".equals(activationResponse)) {
            handleActivationRequired(request, response, session, deviceId, user, token);
        } else if (token != null) {
            handleLoginForActivedUser(request, response, session, deviceId, user, token);
        } else {
            AdminResponses.error(response, 502, "Invalid token or session");
        }
    }

    private void handleActivationRequired(HttpServletRequest request, HttpServletResponse response, HttpSession session,
                                           String deviceId, String user, String token)
            throws ServletException, IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        List<String> token2;
        try {
            token2 = deviceSessionManager.getToken2(deviceId);
        } catch (Exception e) {
            log.error("Error fetching token2", e);
            AdminResponses.error(response, 502, "User does not bear valid parameters");
            return;
        }

        AdminResponses.prepareActivationRequired(response, token2.get(0));

        Map<String, String> attributes = buildAttributes(session, user, token2.get(0));
        callServiceAndRespond(response, request, user, token, attributes);
    }

    private void handleLoginForActivedUser(HttpServletRequest request, HttpServletResponse response, HttpSession session,
                                            String deviceId, String user, String token)
            throws ServletException, IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        List<String> token2;
        try {
            token2 = deviceSessionManager.getToken2(deviceId);
        } catch (Exception e) {
            log.error("Error fetching token2", e);
            throw new ServletException(e.getCause().toString());
        }

        Map<String, String> attributes = buildAttributes(session, user, token2.get(0));
        if (isNewsSettingsRequest(request)) {
            callNewsSettingsAndRespond(response, request, attributes);
        } else {
            callServiceAndRespond(response, request, user, token, attributes);
        }
    }

    private void callNewsSettingsAndRespond(HttpServletResponse response, HttpServletRequest request,
                                            Map<String, String> attributes)
            throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        ServiceClient client = new ServiceClient(SystemConstants.getServiceUrl() + "/mbook-1", request, attributes);
        int status;
        String contentType;
        String responseBody;
        try {
            Response apiResponse;
            if ("PUT".equals(request.getMethod())) {
                StringWriter body = new StringWriter();
                request.getReader().transferTo(body);
                apiResponse = client.callPutNewsScreen(body.toString());
            } else {
                apiResponse = client.callGetNewsScreen();
            }
            try (Response upstream = apiResponse) {
                status = upstream.getStatus();
                contentType = upstream.getMediaType() == null
                        ? "application/json" : upstream.getMediaType().toString();
                responseBody = upstream.hasEntity() ? upstream.readEntity(String.class) : "";
            }
        } finally {
            client.close();
        }
        AdminResponses.newsSettingsDownstream(response, status, contentType, responseBody);
    }

    private Map<String, String> buildAttributes(HttpSession session, String user, String token2) {
        Map<String, String> attributes = new HashMap<>();
        attributes.put("user", user);
        attributes.put("token2", token2);
        attributes.put("TIME_", String.valueOf(session.getCreationTime()));
        return attributes;
    }

    private void callServiceAndRespond(HttpServletResponse response, HttpServletRequest request, String user,
                                        String token, Map<String, String> attributes)
            throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        String serviceUrl = SystemConstants.getServiceUrl();
        ServiceClient client = new ServiceClient(serviceUrl + "/mbook-1", request, attributes);
        Response apiResponse = client.callGetData(user.trim(), token.trim());
        String responseBody = apiResponse.readEntity(String.class);
        client.close();

        AdminResponses.downstreamBody(response, responseBody);
    }
}
