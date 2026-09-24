package com.dalogin.servlets.responsemap;

import jakarta.servlet.http.HttpServletResponse;
import org.json.JSONArray;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * Endpoint response helper for {@code /activeSessions}. Wraps the already-serialized sessions
 * array in the exact content-type/status shape the original inline write used.
 */
public final class ActiveSessionsResponses {

    private ActiveSessionsResponses() {
    }

    public static void sessionsList(HttpServletResponse response, JSONArray sessions) throws IOException {
        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");
        response.setStatus(HttpServletResponse.SC_OK);
        try (PrintWriter out = response.getWriter()) {
            out.print(sessions.toString());
            out.flush();
        }
    }
}
