package com.dalogin.servlets.responsemap;

import jakarta.servlet.http.HttpServletResponse;
import org.json.JSONObject;

import java.io.IOException;

import static com.dalogin.servlets.support.ServletResponses.writeJson;

/** Named response operations for {@code LoggingOut}. */
public final class LogoutResponses {

    private LogoutResponses() {
    }

    public static void loggedOut(HttpServletResponse response) throws IOException {
        writeJson(response, HttpServletResponse.SC_OK, new JSONObject()
                .put("isLoggedOut", "true")
                .put("Success", "true"));
    }

    public static void alreadyLoggedOut(HttpServletResponse response) throws IOException {
        writeJson(response, HttpServletResponse.SC_OK, new JSONObject()
                .put("isAlreadyLoggedOut", "true")
                .put("Success", "true"));
    }
}
