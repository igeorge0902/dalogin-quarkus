package com.dalogin.servlets.responsemap;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.json.JSONObject;

import java.io.IOException;
import java.io.PrintWriter;

import static com.dalogin.servlets.support.ServletResponses.writeJson;

/**
 * Named response operations for {@code RegistrationWithoutVoucher}. Preserves the existing
 * {@code json.put("X-Token", token2)} bug where the whole two-element list (not
 * {@code token2.get(0)}) is serialized as a JSON array — not corrected here.
 */
public final class RegistrationWithoutVoucherResponses {

    private RegistrationWithoutVoucherResponses() {
    }

    public static void emailValidationFailed(HttpServletResponse response) throws IOException {
        writeJson(response, HttpServletResponse.SC_BAD_GATEWAY, new JSONObject()
                .put("Registration", "failed")
                .put("Email", "false")
                .put("Message", "Not a valid email format!"));
    }

    public static void hmacError(HttpServletResponse response) throws IOException {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "hmac error");
    }

    public static void uniqueConstraintFailed(HttpServletResponse response, String rawBody) throws IOException {
        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
        try (PrintWriter out = response.getWriter()) {
            out.print(rawBody);
            out.flush();
        }
    }

    public static void insertDeviceFailed(HttpServletResponse response) throws IOException {
        writeJson(response, HttpServletResponse.SC_BAD_GATEWAY, new JSONObject().put("Error", "Registration failed"),
                "application/json", "utf-8");
    }

    public static void runtimeFailure(HttpServletResponse response) throws IOException {
        writeJson(response, HttpServletResponse.SC_BAD_GATEWAY, new JSONObject()
                .put("Registration", "failed")
                .put("Email", "false")
                .put("Message", "I have gone to smoke a cigarette!"));
    }

    public static void nativeMobileSucceeded(HttpServletResponse response, RegistrationWithoutVoucherSuccess success)
            throws IOException {
        setXsrfCookie(response, success);
        writeJson(response, HttpServletResponse.SC_OK, new JSONObject()
                .put("success", 1)
                .put("JSESSIONID", success.sessionId())
                .put("X-Token", success.token2()));
    }

    public static void mobileWebviewSucceeded(HttpServletResponse response, RegistrationWithoutVoucherSuccess success,
                                               String redirectContextPath) throws IOException {
        setXsrfCookie(response, success);
        response.addHeader("X-Token", success.token2().get(0));
        // Preserved verbatim: the JSON body is constructed but never written; the redirect is the
        // actual response.
        JSONObject json = new JSONObject()
                .put("Session", "raked")
                .put("Success", "true")
                .put("JSESSIONID", success.sessionId())
                .put("X-Token", success.token2());
        response.sendRedirect(redirectContextPath + "/tabularasa.html?JSESSIONID=" + success.sessionId());
    }

    public static void standardSucceeded(HttpServletResponse response, RegistrationWithoutVoucherSuccess success)
            throws IOException {
        setXsrfCookie(response, success);
        response.addHeader("X-Token", success.token2().get(0));
        try (PrintWriter out = response.getWriter()) {
            JSONObject json = new JSONObject()
                    .put("Session", "raked")
                    .put("Success", "true")
                    .put("X-Token", success.token2());
            out.print(json.toString());
            out.flush();
        }
    }

    private static void setXsrfCookie(HttpServletResponse response, RegistrationWithoutVoucherSuccess success) {
        Cookie cookie = new Cookie("XSRF-TOKEN", success.xsrfToken());
        cookie.setSecure(true);
        cookie.setMaxAge(success.maxAge());
        response.addCookie(cookie);
    }
}
