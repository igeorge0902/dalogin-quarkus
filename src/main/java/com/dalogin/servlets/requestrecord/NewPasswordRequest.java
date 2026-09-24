package com.dalogin.servlets.requestrecord;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Immutable request data for {@code ChangePasswordNewPassword}. {@code email} is read untrimmed;
 * {@code pass} is trimmed unconditionally (NPEs on a missing value, matching the original).
 */
public record NewPasswordRequest(
        String hmac,
        String contentLength,
        String microTime,
        String email,
        String confirmationCode,
        String password,
        String deviceId,
        String ios,
        String userAgent,
        String clientType,
        String encryptedDeviceId
) {
    public static NewPasswordRequest from(HttpServletRequest request) {
        String hmac = request.getHeader("X-HMAC-HASH").trim();
        String contentLength = request.getHeader("Content-Length");
        String microTime = request.getHeader("X-MICRO-TIME").trim();
        String email = request.getParameter("email");
        String confirmationCode = request.getParameter("cC");
        String password = request.getParameter("pass").trim();
        String deviceId = request.getParameter("deviceId").trim();
        String ios = request.getParameter("ios");
        String userAgent = request.getHeader("User-Agent");
        String clientType = request.getHeader("M");
        if (clientType == null) {
            clientType = "";
        }
        String encryptedDeviceId = request.getHeader("M-Device");
        return new NewPasswordRequest(hmac, contentLength, microTime, email, confirmationCode, password, deviceId,
                ios, userAgent, clientType, encryptedDeviceId);
    }
}
