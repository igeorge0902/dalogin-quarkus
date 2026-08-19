package com.dalogin.client;

import com.dalogin.client.filter.RequestFilter;
import com.dalogin.client.filter.ClientCallRequestFilter;
import com.dalogin.client.filter.ClientCallResponseFilter;
import com.dalogin.client.service.Device;
import com.dalogin.client.service.Purchases;
import com.dalogin.client.service.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;

import javax.net.ssl.SSLContext;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.LinkedHashMap;
import java.util.Map;

public class ServiceClient {
    private static final Logger LOG = Logger.getLogger("LOG-HTTP-CLIENT");
    private static final String REDACTED = "***";
    private final ResteasyClient client;
    private User userService;
    private Device deviceService;
    private Purchases purchasesService;
    private ResteasyWebTarget target;

    public ServiceClient(String baseUrl, HttpServletRequest request, Map<String, String> attributes)
            throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, KeyManagementException {
       // SSLContext sslContext = getSslContext();
        client = (ResteasyClient) ResteasyClientBuilder.newBuilder().build();
        target = client.target(baseUrl);
        target.register(new RequestFilter(request, attributes));
        target.register(new ClientCallRequestFilter());
        target.register(new ClientCallResponseFilter());
    }

    private static SSLContext getSslContext() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, KeyManagementException {
        // Path to the self-signed certificate
        String certFile = System.getenv().getOrDefault("CERT_FILE", "/Users/georgegaspar/Documents/certs/localhost/mycert1.cer");
        // Load the certificate into a KeyStore
        InputStream certInputStream = new FileInputStream(certFile);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) cf.generateCertificate(certInputStream);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null); // initialize with empty store
        keyStore.setCertificateEntry("selfsignedcert", cert);
        // Create a TrustManager that trusts the self-signed certificate
        javax.net.ssl.TrustManagerFactory tmf = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);
        // Set the SSL context to use the custom TrustManager
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), new java.security.SecureRandom());
        return sslContext;
    }

    public Response callGetData(String user, String token) {
        logOutboundRequest("callGetData", "GET", "/rest/user/{user}/{token1}",
                Map.of("user", sanitize("user", user), "token1", REDACTED));
        userService = target.proxy(User.class);
        Response response = userService.getData(user, token);
        logOutboundResponse("callGetData", "GET", "/rest/user/{user}/{token1}", response.getStatus());
        return response;
    }

    public Response callGetDevice(String uuid) {
        logOutboundRequest("callGetDevice", "GET", "/rest/device/{uuid}",
                Map.of("uuid", sanitize("uuid", uuid)));
        deviceService = target.proxy(Device.class);
        Response response = deviceService.getData(uuid);
        logOutboundResponse("callGetDevice", "GET", "/rest/device/{uuid}", response.getStatus());
        return response;
    }

    public Response callGetPurchases() {
        logOutboundRequest("callGetPurchases", "GET", "/rest/book/purchases", Map.of());
        purchasesService = target.proxy(Purchases.class);
        Response response = purchasesService.getAllPurchases();
        logOutboundResponse("callGetPurchases", "GET", "/rest/book/purchases", response.getStatus());
        return response;
    }

    public Response callGetTickets(String purchaseId) {
        logOutboundRequest("callGetTickets", "GET", "/rest/book/purchases/tickets",
                Map.of("purchaseId", sanitize("purchaseId", purchaseId)));
        purchasesService = target.proxy(Purchases.class);
        Response response = purchasesService.getTickets(purchaseId);
        logOutboundResponse("callGetTickets", "GET", "/rest/book/purchases/tickets", response.getStatus());
        return response;
    }

    public Response managePurchases(HttpServletRequest request) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("purchaseId", sanitize("purchaseId", request.getParameter("purchaseId")));
        params.put("ticketsToBeCancelled", sanitize("ticketsToBeCancelled", request.getParameter("ticketsToBeCancelled")));
        logOutboundRequest("managePurchases", "POST", "/rest/book/managepurchases", params);
        purchasesService = target.proxy(Purchases.class);
        Response response = purchasesService.managePurchases(request.getParameter("purchaseId"), request.getParameter("ticketsToBeCancelled"));
        logOutboundResponse("managePurchases", "POST", "/rest/book/managepurchases", response.getStatus());
        return response;
    }

    public Response deletePurchases(HttpServletRequest request) {
        logOutboundRequest("deletePurchases", "POST", "/rest/book/deletepurchases",
                Map.of("purchaseId", sanitize("purchaseId", request.getParameter("purchaseId"))));
        purchasesService = target.proxy(Purchases.class);
        Response response = purchasesService.deletePurchases(request.getParameter("purchaseId"));
        logOutboundResponse("deletePurchases", "POST", "/rest/book/deletepurchases", response.getStatus());
        return response;
    }

    public Response clientToken() {
        logOutboundRequest("clientToken", "GET", "/rest/book/payment/clientToken", Map.of());
        purchasesService = target.proxy(Purchases.class);
        Response response = purchasesService.clientToken();
        logOutboundResponse("clientToken", "GET", "/rest/book/payment/clientToken", response.getStatus());
        return response;
    }

    public Response checkOut(HttpServletRequest request) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("orderId", sanitize("orderId", request.getParameter("orderId")));
        params.put("seatsToBeReserved", sanitize("seatsToBeReserved", request.getParameter("seatsToBeReserved")));
        params.put("payment_method_nonce", sanitize("payment_method_nonce", request.getParameter("payment_method_nonce")));
        logOutboundRequest("checkOut", "POST", "/rest/book/payment/fullcheckout2", params);
        purchasesService = target.proxy(Purchases.class);
        Response response = purchasesService.checkOut(request.getParameter("orderId"), request.getParameter("seatsToBeReserved"), request.getParameter("payment_method_nonce"));
        logOutboundResponse("checkOut", "POST", "/rest/book/payment/fullcheckout2", response.getStatus());
        return response;
    }

    public void close() {
        client.close();
    }

    private void logOutboundRequest(String clientMethod, String method, String path, Map<String, String> params) {
        LOG.debugf("event=OUTBOUND_START clientMethod=%s method=%s uri=%s path=%s params=%s",
                clientMethod, method, target.getUri(), path, params);
    }

    private void logOutboundResponse(String clientMethod, String method, String path, int status) {
        LOG.debugf("event=OUTBOUND_END clientMethod=%s method=%s uri=%s path=%s status=%d",
                clientMethod, method, target.getUri(), path, status);
    }

    private String sanitize(String name, String value) {
        if (value == null) {
            return "null";
        }
        String lower = name.toLowerCase();
        if (lower.contains("token") || lower.contains("ciphertext") || lower.equals("uuid")) {
            return REDACTED;
        }
        if (lower.contains("nonce")) {
            return maskNonce(value);
        }
        return value;
    }

    private String maskNonce(String nonce) {
        if (nonce == null || nonce.isEmpty()) {
            return "null";
        }
        if (nonce.length() <= 8) {
            return REDACTED;
        }
        return nonce.substring(0, 4) + "..." + nonce.substring(nonce.length() - 4);
    }
}
