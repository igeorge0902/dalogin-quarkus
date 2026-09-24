package com.dalogin.servlets.requestrecord;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Immutable request data for {@code ChangePassword}. Mirrors the exact original field reads:
 * {@code contentLength} is deliberately not trimmed (unlike {@code hmac}/{@code time}), and
 * {@code email} is read untrimmed so the caller can distinguish "missing" from "blank" before
 * trimming it itself.
 */
public record ForgotPasswordRequest(
        String hmac,
        String contentLength,
        String microTime,
        String rawEmail,
        String deviceId,
        String ios,
        String userAgent,
        String clientType,
        String encryptedDeviceId
) {
    public static ForgotPasswordRequest from(HttpServletRequest request) {
        String hmac = request.getHeader("X-HMAC-HASH").trim();
        String contentLength = request.getHeader("Content-Length");
        String microTime = request.getHeader("X-MICRO-TIME").trim();
        String rawEmail = request.getParameter("email");
        String deviceId = request.getParameter("deviceId").trim();
        String ios = request.getParameter("ios");
        String userAgent = request.getHeader("User-Agent");
        String clientType = request.getHeader("M");
        if (clientType == null) {
            clientType = "";
        }
        String encryptedDeviceId = request.getHeader("M-Device");
        return new ForgotPasswordRequest(hmac, contentLength, microTime, rawEmail, deviceId, ios, userAgent,
                clientType, encryptedDeviceId);
    }
}
