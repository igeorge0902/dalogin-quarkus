package com.dalogin.servlets.responsemap;

import jakarta.servlet.http.HttpServletResponse;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.util.Map;

import static com.dalogin.servlets.support.ServletResponses.writeJson;

/**
 * Named response operations for {@code RegActivation}. Both endpoints (POST for triggering the
 * activation email, GET for consuming the activation link) share the {@code /activation} path but
 * have unrelated response shapes.
 */
public final class ActivationResponses {

    private ActivationResponses() {
    }

    public static void emailSent(HttpServletResponse response, String email) throws IOException {
        writeJson(response, HttpServletResponse.SC_OK, new JSONObject()
                .put("Success", "true")
                .put("Email was sent to:", email));
    }

    public static void preconditionFailed(HttpServletResponse response) throws IOException {
        response.sendError(HttpServletResponse.SC_PRECONDITION_FAILED, "Line 125");
    }

    public static void activationFailed(HttpServletResponse response) throws IOException {
        writeJson(response, HttpServletResponse.SC_BAD_GATEWAY, new JSONObject().put("Error", "activation_failed"));
    }

    public static void activationCompleted(HttpServletResponse response, Map<String, String> queryMap) throws IOException {
        JSONArray list = new JSONArray();
        list.put(queryMap);
        writeJson(response, HttpServletResponse.SC_OK, new JSONObject()
                .put("activation", list)
                .put("Registration:", "active"));
    }
}
