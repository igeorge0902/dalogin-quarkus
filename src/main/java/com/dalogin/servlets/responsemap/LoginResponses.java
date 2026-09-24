package com.dalogin.servlets.responsemap;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.json.JSONObject;

import java.io.IOException;

import static com.dalogin.servlets.support.ServletResponses.writeJson;

/**
 * Named response operations for {@code HelloWorld}. Preserves the existing cookie asymmetry
 * (only {@code XSRF-TOKEN} is HTTP-only and path-scoped), the numeric-vs-string {@code Success}
 * JSON value type split between mobile and web clients, and the failure bodies byte-for-byte.
 */
public final class LoginResponses {

    private LoginResponses() {
    }

    public static void missingRequiredInput(HttpServletResponse response) throws IOException {
        writeJson(
                response,
                HttpServletResponse.SC_BAD_GATEWAY,
                new JSONObject()
                        .put("Success", "false")
                        .put("Message", "Missing required headers or parameters")
        );
    }

    public static void authenticationFailed(HttpServletResponse response) throws IOException {
        writeJson(
                response,
                HttpServletResponse.SC_BAD_GATEWAY,
                new JSONObject()
                        .put("Session creation", "failed")
                        .put("Success", "false")
        );
    }

    public static void sessionPersistenceFailed(HttpServletResponse response) throws IOException {
        writeJson(
                response,
                HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                new JSONObject()
                        .put("Success", "false")
                        .put("Message", "Session creation failed")
        );
    }

    public static void loginSucceeded(HttpServletResponse response, LoginSuccess success) throws IOException {
        Cookie cookieXSRF = new Cookie("XSRF-TOKEN", success.xsrfToken());
        cookieXSRF.setSecure(true);
        cookieXSRF.setHttpOnly(true);
        cookieXSRF.setMaxAge(success.maxAge());
        cookieXSRF.setPath(success.contextPath());

        Cookie cookieToken = new Cookie("X-Token", success.token());
        cookieToken.setSecure(true);
        cookieToken.setMaxAge(success.maxAge());

        response.addCookie(cookieXSRF);
        response.addCookie(cookieToken);
        response.addHeader("X-Token", success.token());

        JSONObject body = success.mobileClient()
                ? new JSONObject()
                        .put("success", 1)
                        .put("JSESSIONID", success.sessionId())
                        .put("X-Token", success.token())
                : new JSONObject()
                        .put("Session", "raked")
                        .put("Success", "true")
                        .put("X-Token", success.token());

        writeJson(response, HttpServletResponse.SC_OK, body);
    }
}
