package com.dalogin.servlets;

import com.dalogin.SQLAccess;
import com.dalogin.SystemConstants;
import com.dalogin.client.ServiceClient;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.*;
import jakarta.ws.rs.core.Response;
import org.apache.log4j.Logger;
import org.json.JSONObject;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.*;

@WebServlet(urlPatterns = "/admin", name = "AdminServlet")
public class AdminServlet extends HttpServlet {
    private static final long serialVersionUID = 5570497466931245289L;
    private static final Logger log = Logger.getLogger(AdminServlet.class);
    private static final String APPLICATION_JSON = "application/json";
    private static final String UTF_8 = "utf-8";

    @Override
    public void init() throws ServletException {
        // Initialization logic if needed
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        processRequest(request, response);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        processRequest(request, response);
    }

    private void processRequest(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        HttpSession session = request.getSession(false);
        String sessionId = Optional.ofNullable(request.getParameter("JSESSIONID")).orElseGet(() -> session != null ? session.getId() : null);
        log.info("SessionId from the request parameter: " + sessionId);

        try {
            performTask(request, response, session);
        } catch (Exception e) {
            log.error("Error during task execution", e);
            sendErrorResponse(response, 502, "Internal server error");
        }
    }

    private void performTask(HttpServletRequest request, HttpServletResponse response, HttpSession session) throws Exception {
        if (session == null) {
            sendErrorResponse(response, 502, "Session is invalid");
            return;
        }

        ServletContext context = session.getServletContext();
        String deviceId = (String) session.getAttribute("deviceId");
        String user = (String) session.getAttribute("user");

        if (deviceId == null || user == null) {
            sendErrorResponse(response, 502, "Missing deviceId or user in session");
            return;
        }

        String token = SQLAccess.getToken(deviceId, context);
        String activationResponse = SQLAccess.checkActivation(user, context);

        if ("S".equals(activationResponse)) {
            handleActivationRequired(request, response, session, context, deviceId, user, token);
        } else if (token != null) {
            handleLoginForActivedUser(request, response, session, context, deviceId, user, token);
        } else {
            sendErrorResponse(response, 502, "Invalid token or session");
        }
    }

    private void handleActivationRequired(HttpServletRequest request, HttpServletResponse response, HttpSession session, ServletContext context, String deviceId, String user, String token) throws ServletException, IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        List<String> token2;
        try {
            token2 = SQLAccess.getToken2(deviceId, context);
        } catch (Exception e) {
            log.error("Error fetching token2", e);
            sendErrorResponse(response, 502, "User does not bear valid parameters");
            return;
        }

        response.setContentType(APPLICATION_JSON);
        response.setCharacterEncoding(UTF_8);
        response.setHeader("Response", "S");
        response.setStatus(300);
        response.addHeader("X-Token", token2.get(0));

        Map<String, String> attributes = buildAttributes(session, user, token2.get(0));
        callServiceAndRespond(response, request, context, user, token, attributes);
    }

    private void handleLoginForActivedUser(HttpServletRequest request, HttpServletResponse response, HttpSession session, ServletContext context, String deviceId, String user, String token) throws ServletException, IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        List<String> token2;
        try {
            token2 = SQLAccess.getToken2(deviceId, context);
        } catch (Exception e) {
            log.error("Error fetching token2", e);
            throw new ServletException(e.getCause().toString());
        }

        Map<String, String> attributes = buildAttributes(session, user, token2.get(0));
        callServiceAndRespond(response, request, context, user, token, attributes);
    }

    private Map<String, String> buildAttributes(HttpSession session, String user, String token2) {
        Map<String, String> attributes = new HashMap<>();
        attributes.put("user", user);
        attributes.put("token2", token2);
        attributes.put("TIME_", String.valueOf(session.getCreationTime()));
        return attributes;
    }

    private void callServiceAndRespond(HttpServletResponse response, HttpServletRequest request, ServletContext context, String user, String token, Map<String, String> attributes) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
       // String webApiContext = context.getInitParameter("webApiContext");
        String serviceUrl = SystemConstants.getServiceUrl();
        ServiceClient client = new ServiceClient(serviceUrl + "/mbook-1", request, attributes);
        Response apiResponse = client.callGetData(user.trim(), token.trim());
        String responseBody = apiResponse.readEntity(String.class);
        client.close();

        PrintWriter out = response.getWriter();
        out.print(responseBody);
        out.flush();
    }

    private void sendErrorResponse(HttpServletResponse response, int statusCode, String errorMessage) throws IOException {
        response.setContentType(APPLICATION_JSON);
        response.setCharacterEncoding(UTF_8);
        response.setStatus(statusCode);

        JSONObject json = new JSONObject();
        json.put("Error Message", errorMessage);
        json.put("Success", false);

        PrintWriter out = response.getWriter();
        out.print(json.toString());
        out.flush();
    }

    @Override
    public void destroy() {
        // Cleanup logic if needed
    }
}
