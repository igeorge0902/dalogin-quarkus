package com.dalogin.servlets.requestrecord;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Immutable request data for {@code ChangePasswordCode}. {@code email} is deliberately read and
 * used untrimmed, matching the original servlet exactly.
 */
public record ForgotPasswordCodeRequest(
        String hmac,
        String contentLength,
        String microTime,
        String email,
        String confirmationCode,
        String deviceId,
        String ios,
        String userAgent,
        String clientType,
        String encryptedDeviceId
) {
    public static ForgotPasswordCodeRequest from(HttpServletRequest request) {
        String hmac = request.getHeader("X-HMAC-HASH").trim();
        String contentLength = request.getHeader("Content-Length");
        String microTime = request.getHeader("X-MICRO-TIME").trim();
        String email = request.getParameter("email");
        String confirmationCode = request.getParameter("cC");
        String deviceId = request.getParameter("deviceId").trim();
        String ios = request.getParameter("ios");
        String userAgent = request.getHeader("User-Agent");
        String clientType = request.getHeader("M");
        if (clientType == null) {
            clientType = "";
        }
        String encryptedDeviceId = request.getHeader("M-Device");
        return new ForgotPasswordCodeRequest(hmac, contentLength, microTime, email, confirmationCode, deviceId,
                ios, userAgent, clientType, encryptedDeviceId);
    }
}
