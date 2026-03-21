package com.dalogin.client.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class RequestFilter implements ClientRequestFilter {
    private HttpServletRequest request;
    private Map<String, String> attributes;

    public RequestFilter(HttpServletRequest request, Map<String, String> attributes) {
        this.request = request;
        this.attributes = attributes;
    }

    @Override
    public void filter(ClientRequestContext requestContext) throws IOException {
        requestContext.getHeaders().add("X-Token", request.getHeader("X-Token"));
        // Ciphertext must match token2 for the downstream CiphertextFilter.
        // Browser proxy requests (CheckOut, GetAllPurchases, ManagePurchases) don't carry
        // a Ciphertext header — fall back to the token2 attribute value.
        String ciphertext = request.getHeader("Ciphertext");
        if (ciphertext == null || ciphertext.isEmpty()) {
            ciphertext = attributes.get("token2");
        }
        requestContext.getHeaders().add("Ciphertext", ciphertext);
        Set attributeSet = attributes.keySet();
        List<String> attributeList = attributeSet.stream().toList();
        for (int i = 0; i < attributes.size(); i++) {
            requestContext.getHeaders().add(attributeList.get(i), attributes.get(attributeList.get(i)));
        }
        jakarta.servlet.http.Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (jakarta.servlet.http.Cookie cookie : cookies) {
                requestContext.getHeaders().add("Cookie", cookie.getName() + "=" + cookie.getValue());
            }
        }
    }
}
