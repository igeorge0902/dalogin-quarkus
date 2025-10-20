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

@WebServlet(urlPatterns = "/CheckOut", name = "CheckOut")
public class CheckOut extends HttpServlet implements Serializable {

    private static final long serialVersionUID = 2152364900906190486L;
    private static final Logger log = Logger.getLogger(CheckOut.class);

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // GET -> retrieve a client token for the UI to use during checkout
        response.setContentType("application/json;charset=UTF-8");
        HttpSession session = request.getSession();
        ServletContext context = request.getServletContext();
        String webApi2Context = context.getInitParameter("webApi2Context");
        Map<String, String> attributes = buildAuthAttributes(session, context);

        String serviceUrl = SystemConstants.getServiceUrl() + webApi2Context;

        ServiceClient client = null;
        String responseBody = "{}";
        try {
            client = new ServiceClient(serviceUrl, request, attributes);
            // IMPORTANT: this returns the client token (e.g. for the UI to initialize a payment widget)
            Response apiResponse = client.clientToken();
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
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // POST -> perform the checkout. The UI is expected to set the payment token/nonce on the request.
        // (e.g. request parameter "paymentToken" or a form field — ServiceClient.checkOut reads the request)
        response.setContentType("application/json;charset=UTF-8");
        HttpSession session = request.getSession();
        ServletContext context = request.getServletContext();
        String webApi2Context = context.getInitParameter("webApi2Context");
        Map<String, String> attributes = buildAuthAttributes(session, context);

        String serviceUrl = SystemConstants.getServiceUrl() + webApi2Context;

        ServiceClient client = null;
        String responseBody = "{}";
        try {
            client = new ServiceClient(serviceUrl, request, attributes);
            // ServiceClient.checkOut should extract the payment token set by the UI from the request
            Response apiResponse = client.checkOut(request);
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
     * Build authentication attributes required by the service client.
     * Throws ServletException if tokens/UUID cannot be retrieved.
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
            log.warn("Missing token2 for user/session");
            throw new ServletException("Missing authentication token");
        }

        Map<String, String> attributes = new HashMap<>();
        attributes.put("uuid", uuid);
        attributes.put("token2", token2.get(0));
        attributes.put("TIME_", String.valueOf(session.getCreationTime()));
        return attributes;
    }
}