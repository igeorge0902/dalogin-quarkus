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

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Serializable;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@WebServlet(urlPatterns = "/GetAllPurchases", name = "GetAllPurchases")
public class GetAllPurchases extends HttpServlet implements Serializable {

    private static final long serialVersionUID = 2152364900906190486L;
    private static final Logger log = Logger.getLogger(GetAllPurchases.class);

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json;charset=UTF-8");

        HttpSession session = request.getSession();
        String sessionId = request.getParameter("JSESSIONID");
        if (sessionId == null) {
            sessionId = session.getId();
        }
        log.debug("Session ID: " + sessionId);

        ServletContext context = request.getServletContext();

        // Fetch security tokens
        String deviceId = (String) session.getAttribute("deviceId");
        String user = (String) session.getAttribute("user");

        String uuid;
        List<String> token2;
        try {
            token2 = SQLAccess.getToken2(deviceId, context);
            uuid = SQLAccess.getUUID(user, context);
        } catch (Exception e) {
            log.error("Error fetching user data", e);
            throw new ServletException("Unable to fetch user data", e);
        }

        if (token2 == null || token2.isEmpty()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing authentication token");
            return;
        }

        Map<String, String> attributes = new HashMap<>();
        attributes.put("uuid", uuid);
        attributes.put("token2", token2.get(0));
        attributes.put("TIME_", String.valueOf(session.getCreationTime()));

        String serviceUrl = SystemConstants.getServiceUrl() + "/mbooks-1";
        String responseBody;
        ServiceClient client = null;

        try {
            client = new ServiceClient(serviceUrl, request, attributes);
            Response apiResponse = client.callGetPurchases();
            responseBody = apiResponse.readEntity(String.class);
        } catch (CertificateException | KeyStoreException |
                 NoSuchAlgorithmException | KeyManagementException e) {
            log.error("SSL configuration error", e);
            throw new ServletException("SSL configuration error", e);
        } finally {
            if (client != null) {
                client.close();
            }
        }

        try (PrintWriter out = response.getWriter()) {
            out.print(responseBody);
        }
    }
}
