package com.dalogin.servlets.requestrecord;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Immutable request data for {@code RegistrationWithoutVoucher}. Distinct from
 * {@code RegistrationRequest} because this endpoint has no voucher field and a different HMAC
 * computation; sharing would create nullable fields only one endpoint uses.
 */
public record RegistrationWithoutVoucherRequest(
        String hmac,
        String contentLength,
        String microTime,
        String user,
        String password,
        String email,
        String deviceId,
        String ios,
        String webView,
        String clientType
) {
    public static RegistrationWithoutVoucherRequest from(HttpServletRequest request) {
        String user = request.getParameter("user").trim();
        String pass = request.getParameter("pswrd").trim();
        String email = request.getParameter("email").trim();
        String deviceId = request.getParameter("deviceId").trim();
        String hmac = request.getHeader("X-HMAC-HASH");
        String contentLength = request.getHeader("Content-Length");
        String time = request.getHeader("X-MICRO-TIME");
        String ios = request.getParameter("ios");
        String webView = request.getHeader("User-Agent");
        String clientType = request.getHeader("M");
        if (clientType == null) {
            clientType = "";
        }
        return new RegistrationWithoutVoucherRequest(hmac, contentLength, time, user, pass, email, deviceId,
                ios, webView, clientType);
    }

    public boolean mobileClient() {
        return ios != null;
    }

    public boolean mobileWebview() {
        return webView != null && webView.contains("Mobile") && "M".equals(clientType);
    }
}
