package com.dalogin.client;

import com.dalogin.client.filter.RequestFilter;
import com.dalogin.client.service.Device;
import com.dalogin.client.service.Purchases;
import com.dalogin.client.service.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.james.mime4j.message.MultipartBuilder;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;
import org.jboss.resteasy.plugins.providers.multipart.MultipartFormDataWriter;
import org.json.JSONObject;

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
import java.util.Map;

public class ServiceClient {
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
        userService = target.proxy(User.class);
        Response response = userService.getData(user, token);
        return response;
    }

    public Response callGetDevice(String uuid) {
        deviceService = target.proxy(Device.class);
        Response response = deviceService.getData(uuid);
        return response;
    }

    public Response callGetPurchases() {
        purchasesService = target.proxy(Purchases.class);
        Response response = purchasesService.getAllPurchases();
        return response;
    }

    public Response callGetTickets(String purchaseId) {
        purchasesService = target.proxy(Purchases.class);
        Response response = purchasesService.getTickets(purchaseId);
        return response;
    }

    public Response managePurchases(HttpServletRequest request) {
        purchasesService = target.proxy(Purchases.class);
        Response response = purchasesService.managePurchases(request.getParameter("purchaseId"), request.getParameter("ticketsToBeCancelled"));
        return response;
    }

    public Response deletePurchases(HttpServletRequest request) {
        purchasesService = target.proxy(Purchases.class);
        Response response = purchasesService.deletePurchases(request.getParameter("purchaseId"));
        return response;
    }

    public Response clientToken() {
        purchasesService = target.proxy(Purchases.class);
        Response response = purchasesService.clientToken();
        return response;
    }

    public Response checkOut(HttpServletRequest request) {
        purchasesService = target.proxy(Purchases.class);
        Response response = purchasesService.checkOut(request.getParameter("orderId"), request.getParameter("seatsToBeReserved"), request.getParameter("payment_method_nonce"));
        return response;
    }

    public void close() {
        client.close();
    }
}
