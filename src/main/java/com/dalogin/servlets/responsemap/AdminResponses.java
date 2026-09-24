package com.dalogin.servlets.responsemap;

import jakarta.servlet.http.HttpServletResponse;
import org.json.JSONObject;

import java.io.IOException;

import static com.dalogin.servlets.support.ServletResponses.writeRaw;

/** Named response operations for {@code AdminServlet}. */
public final class AdminResponses {

    private static final String APPLICATION_JSON = "application/json";
    private static final String UTF_8 = "utf-8";

    private AdminResponses() {
    }

    public static void error(HttpServletResponse response, int statusCode, String errorMessage) throws IOException {
        response.setContentType(APPLICATION_JSON);
        response.setCharacterEncoding(UTF_8);
        response.setStatus(statusCode);

        JSONObject json = new JSONObject();
        json.put("Error Message", errorMessage);
        json.put("Success", false);

        writeRaw(response, json.toString());
    }

    /** Sets the activation-required response headers; the caller then streams the downstream body. */
    public static void prepareActivationRequired(HttpServletResponse response, String token) {
        response.setContentType(APPLICATION_JSON);
        response.setCharacterEncoding(UTF_8);
        response.setHeader("Response", "S");
        response.setStatus(300);
        response.addHeader("X-Token", token);
    }

    public static void downstreamBody(HttpServletResponse response, String body) throws IOException {
        writeRaw(response, body);
    }
}
