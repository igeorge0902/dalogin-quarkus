package com.dalogin.servlets;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2017
 */

import com.dalogin.SystemConstants;
import com.dalogin.client.ServiceClient;
import com.dalogin.persistence.account.AccountManager;
import com.dalogin.persistence.devicesession.DeviceSessionManager;
import com.dalogin.servlets.responsemap.PurchaseResponses;
import jakarta.inject.Inject;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@WebServlet(urlPatterns = "/GetAllPurchases", name = "GetAllPurchases")
public class GetAllPurchases extends HttpServlet implements Serializable {
    private static final long serialVersionUID = 2152364900906190486L;
    private static final Logger log = Logger.getLogger(GetAllPurchases.class);

    @Inject
    DeviceSessionManager deviceSessionManager;

    @Inject
    AccountManager accountManager;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String servletName = getServletName();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        log.debugf("HTTP request started: servlet=%s, method=%s, uri=%s", servletName, method, uri);
        try {
            String responseBody;
            String uuid;
            List<String> token2;
            response.setContentType("application/json;charset=UTF-8");
            HttpSession session = request.getSession();
            ServletContext context = request.getServletContext();
            String deviceId = (String) session.getAttribute("deviceId");
            String user = (String) session.getAttribute("user");
            try {
                token2 = deviceSessionManager.getToken2(deviceId);
                uuid = accountManager.getUUID(user);
            } catch (Exception e) {
                log.error("Error fetching user data", e);
                throw new ServletException("Unable to fetch user data", e);
            }
            if (token2 == null || token2.isEmpty()) {
                response.sendError(401, "Missing authentication token");
                return;
            }
            Map<String, String> attributes = new HashMap<>();
            attributes.put("uuid", uuid);
            attributes.put("token2", token2.get(0));
            attributes.put("TIME_", String.valueOf(session.getCreationTime()));
            String serviceUrl = SystemConstants.getServiceUrl() + "/mbooks-1";
            ServiceClient client = createClient(serviceUrl, request, attributes);
            Response apiResponse = client.callGetPurchases();
            responseBody = apiResponse.readEntity(String.class);
            client.close();
            PurchaseResponses.downstreamBody(response, responseBody);
        } finally {
            log.debugf("HTTP request completed: method=%s, uri=%s, status=%d", method, uri, response.getStatus());
        }
    }

    private ServiceClient createClient(String serviceUrl, HttpServletRequest request, Map<String, String> attributes) throws ServletException {
        try {
            return new ServiceClient(serviceUrl, request, attributes);
        } catch (Exception e) {
            throw new ServletException("Unable to create service client", e);
        }
    }
}
