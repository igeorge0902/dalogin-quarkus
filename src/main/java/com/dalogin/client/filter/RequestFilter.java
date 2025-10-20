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
        requestContext.getHeaders().add("Ciphertext", request.getHeader("Ciphertext"));
        Set attributeSet = attributes.keySet();
        List<String> attributeList = attributeSet.stream().toList();
        for (int i = 0; i < attributes.size(); i++) {
            requestContext.getHeaders().add(attributeList.get(i), attributes.get(attributeList.get(i)));
        }
        for (jakarta.servlet.http.Cookie cookie : request.getCookies()) {
            requestContext.getHeaders().add("Cookie", cookie.getName() + "=" + cookie.getValue());
        }
    }
}