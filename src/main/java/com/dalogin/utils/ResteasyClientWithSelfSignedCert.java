package com.dalogin.utils;

import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Response;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;

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

public class ResteasyClientWithSelfSignedCert {
    public static void main(String[] args) throws Exception {
        SSLContext sslContext = getSslContext();
        // Configure the Resteasy Client to use the SSL context
        ResteasyClient client = (ResteasyClient) ResteasyClientBuilder
                .newBuilder()
                .sslContext(sslContext)
                .build();
        // Target the REST endpoint
        WebTarget target = client.target("https://milo.crabdance.com/mbooks-1/rest/book/locations");
        // Make a request
        Response response = target.request().get();
        // Print the response
        System.out.println("Response status: " + response.getStatus());
        System.out.println("Response body: " + response.readEntity(String.class));
        response.close();
    }

    private static SSLContext getSslContext() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, KeyManagementException {
        // Path to the self-signed certificate
        String certFile = "/Users/georgegaspar/Documents/certs/localhost/mycert1.cer";
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
}
