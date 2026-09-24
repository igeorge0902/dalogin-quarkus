package com.dalogin.servlets.responsemap;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.json.JSONObject;

import java.io.IOException;
import java.io.PrintWriter;

import static com.dalogin.servlets.support.ServletResponses.writeJson;
import static com.dalogin.servlets.support.ServletResponses.writeRaw;

/**
 * Named response operations for {@code Registration}. The XSRF cookie here is secure and
 * max-age only (no HTTP-only/path), which differs from {@code HelloWorld}'s cookie shape — an
 * existing baseline asymmetry, not a defect. The mobile-webview branch never writes its
 * constructed JSON body; it redirects instead, and that unused-object shape is preserved
 * verbatim rather than "corrected".
 */
public final class RegistrationResponses {

    private RegistrationResponses() {
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
        writeRaw(response, rawBody);
    }

    public static void wrapUpFailed(HttpServletResponse response) throws IOException {
        writeJson(response, HttpServletResponse.SC_BAD_GATEWAY, new JSONObject().put("Error", "Registration failed"),
                "application/json", "utf-8");
    }

    public static void runtimeFailure(HttpServletResponse response) throws IOException {
        writeJson(response, HttpServletResponse.SC_BAD_GATEWAY, new JSONObject()
                .put("Registration", "failed")
                .put("Email", "false")
                .put("Message", "I have gone to smoke a cigarette!"));
    }

    public static void nativeMobileSucceeded(HttpServletResponse response, RegistrationSuccess success)
            throws IOException {
        setXsrfCookie(response, success);
        writeJson(response, HttpServletResponse.SC_OK, new JSONObject()
                .put("success", 1)
                .put("JSESSIONID", success.sessionId())
                .put("X-Token", success.token()));
    }

    public static void mobileWebviewSucceeded(HttpServletResponse response, RegistrationSuccess success,
                                               String redirectContextPath) throws IOException {
        setXsrfCookie(response, success);
        response.addHeader("X-Token", success.token());
        // Preserved verbatim: this JSON object is constructed but never written; the redirect is
        // the actual response.
        JSONObject json = new JSONObject()
                .put("Session", "raked")
                .put("Success", "true")
                .put("JSESSIONID", success.sessionId())
                .put("X-Token", success.token());
        response.sendRedirect(redirectContextPath + "/tabularasa.html?JSESSIONID=" + success.sessionId());
    }

    public static void standardSucceeded(HttpServletResponse response, RegistrationSuccess success)
            throws IOException {
        setXsrfCookie(response, success);
        response.addHeader("X-Token", success.token());
        try (PrintWriter out = response.getWriter()) {
            JSONObject json = new JSONObject()
                    .put("Session", "raked")
                    .put("Success", "true")
                    .put("JSESSIONID", success.sessionId())
                    .put("X-Token", success.token());
            out.print(json.toString());
            out.flush();
        }
    }

    private static void setXsrfCookie(HttpServletResponse response, RegistrationSuccess success) {
        Cookie cookie = new Cookie("XSRF-TOKEN", success.xsrfToken());
        cookie.setSecure(true);
        cookie.setMaxAge(success.maxAge());
        response.addCookie(cookie);
    }
}
