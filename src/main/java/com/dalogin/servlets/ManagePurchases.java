package com.dalogin.servlets;

import com.dalogin.SQLAccess;
import com.dalogin.SystemConstants;
import com.dalogin.client.ServiceClient;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
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

@WebServlet(urlPatterns = "/ManagePurchases", name = "ManagePurchases")
public class ManagePurchases extends HttpServlet implements Serializable {

    private static final long serialVersionUID = 2152364900906190486L;
    private static final Logger log = Logger.getLogger(ManagePurchases.class);

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("application/json;charset=UTF-8");

        HttpSession session = request.getSession();
        ServletContext context = request.getServletContext();
        String webApi2Context = context.getInitParameter("webApi2Context");
        Map<String, String> attributes = buildAuthAttributes(session, context);

        String serviceUrl = SystemConstants.getServiceUrl() + webApi2Context;
        ServiceClient client = null;
        String responseBody;

        try {
            client = new ServiceClient(serviceUrl, request, attributes);

            Response apiResponse;
            if (request.getParameter("ticketsToBeCancelled") != null) {
                apiResponse = client.managePurchases(request);
            } else {
                apiResponse = client.deletePurchases(request);
            }
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

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("application/json;charset=UTF-8");

        HttpSession session = request.getSession();
        ServletContext context = request.getServletContext();
        String webApi2Context = context.getInitParameter("webApi2Context");
        Map<String, String> attributes = buildAuthAttributes(session, context);

        String serviceUrl = SystemConstants.getServiceUrl() + webApi2Context;
        ServiceClient client = null;
        String responseBody;

        try {
            client = new ServiceClient(serviceUrl, request, attributes);

            String purchaseId = request.getParameter("purchaseId");
            Response apiResponse = client.callGetTickets(purchaseId);
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

    /**
     * Retrieve authentication/authorization attributes for API calls.
     */
    private Map<String, String> buildAuthAttributes(HttpSession session, ServletContext context)
            throws ServletException {
        String deviceId = (String) session.getAttribute("deviceId");
        String user = (String) session.getAttribute("user");

        List<String> token2;
        String uuid;
        try {
            token2 = SQLAccess.getToken2(deviceId, context);
            uuid = SQLAccess.getUUID(user, context);
        } catch (Exception e) {
            log.error("Error fetching tokens/UUID", e);
            throw new ServletException("Unable to fetch user data", e);
        }

        if (token2 == null || token2.isEmpty()) {
            throw new ServletException("Missing authentication token");
        }

        Map<String, String> attributes = new HashMap<>();
        attributes.put("uuid", uuid);
        attributes.put("token2", token2.get(0));
        attributes.put("TIME_", String.valueOf(session.getCreationTime()));
        return attributes;
    }
}
