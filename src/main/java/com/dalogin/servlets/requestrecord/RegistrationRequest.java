package com.dalogin.servlets.requestrecord;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Immutable request data for {@code Registration} (voucher path). Field reads and the unconditional
 * {@code .trim()} calls mirror the original Servlet exactly, including the fact that a missing
 * required parameter/header surfaces as an uncaught {@code NullPointerException} (existing baseline
 * behavior, not corrected here).
 */
public record RegistrationRequest(
        String hmac,
        String contentLength,
        String microTime,
        String user,
        String password,
        String email,
        String voucher,
        String deviceId,
        String ios,
        String webView,
        String clientType
) {
    public static RegistrationRequest from(HttpServletRequest request) {
        String user = request.getParameter("user").trim();
        String pass = request.getParameter("pswrd").trim();
        String email = request.getParameter("email").trim();
        String voucher = request.getParameter("voucher_").trim();
        String deviceId = request.getParameter("deviceId").trim();
        String hmac = request.getHeader("X-HMAC-HASH").trim();
        String contentLength = request.getHeader("Content-Length").trim();
        String time = request.getHeader("X-MICRO-TIME").trim();
        String ios = request.getParameter("ios");
        String webView = request.getHeader("User-Agent");
        String clientType = request.getHeader("M");
        if (clientType == null) {
            clientType = "";
        }
        return new RegistrationRequest(hmac, contentLength, time, user, pass, email, voucher, deviceId,
                ios, webView, clientType);
    }

    public boolean mobileClient() {
        return ios != null;
    }

    public boolean mobileWebview() {
        return webView != null && webView.contains("Mobile") && "M".equals(clientType);
    }
}
