package com.dalogin.servlets.requestrecord;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Immutable login request data with wire-name mapping and normalization. Preserves the exact
 * source behavior of {@code HelloWorld.doPost}: {@code ios} is a presence check (not trimmed or
 * boolean-converted), missing {@code M} becomes {@code ""}, and {@code X-MICRO-TIME} is only
 * validated for parseability (the parsed value is otherwise unused).
 */
public record LoginRequest(
        String hmac,
        String contentLength,
        String microTime,
        String password,
        String user,
        String deviceId,
        String ios,
        String userAgent,
        String clientType,
        String encryptedDeviceId
) {
    private static final String HMAC_HEADER = "X-HMAC-HASH";
    private static final String MICRO_TIME_HEADER = "X-MICRO-TIME";
    private static final String CLIENT_TYPE_HEADER = "M";
    private static final String ENCRYPTED_DEVICE_HEADER = "M-Device";

    public static LoginRequest from(HttpServletRequest request) {
        return new LoginRequest(
                trim(request.getHeader(HMAC_HEADER)),
                trim(request.getHeader("Content-Length")),
                trim(request.getHeader(MICRO_TIME_HEADER)),
                trim(request.getParameter("pswrd")),
                trim(request.getParameter("user")),
                trim(request.getParameter("deviceId")),
                request.getParameter("ios"),
                request.getHeader("User-Agent"),
                defaultString(request.getHeader(CLIENT_TYPE_HEADER)),
                request.getHeader(ENCRYPTED_DEVICE_HEADER)
        );
    }

    public boolean hasRequiredValues() {
        return hmac != null
                && contentLength != null
                && microTime != null
                && password != null
                && user != null
                && deviceId != null;
    }

    public long validatedMicroTime() {
        return Long.parseLong(microTime);
    }

    public boolean mobileClient() {
        return ios != null;
    }

    private static String trim(String value) {
        return value == null ? null : value.trim();
    }

    private static String defaultString(String value) {
        return value == null ? "" : value;
    }
}
