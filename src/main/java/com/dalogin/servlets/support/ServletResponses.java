package com.dalogin.servlets.support;

import jakarta.servlet.http.HttpServletResponse;
import org.json.JSONObject;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * Shared writer/content-type/status mechanics only. Contains no endpoint payload fields, status
 * choice, exception handling, or request inspection.
 */
public final class ServletResponses {

    private ServletResponses() {
    }

    public static void writeJson(HttpServletResponse response, int status, JSONObject body) throws IOException {
        writeJson(response, status, body, "application/json", "utf-8");
    }

    /**
     * Overload for endpoints whose baseline emits an exact {@code Content-Type} such as
     * {@code application/json;charset=UTF-8} rather than the default two-call form.
     */
    public static void writeJson(HttpServletResponse response, int status, JSONObject body,
                                  String contentType, String characterEncoding) throws IOException {
        response.setContentType(contentType);
        if (characterEncoding != null) {
            response.setCharacterEncoding(characterEncoding);
        }
        response.setStatus(status);
        try (PrintWriter out = response.getWriter()) {
            out.print(body.toString());
            out.flush();
        }
    }

    /**
     * Streams an already-serialized body (e.g. a downstream service's raw JSON response) without
     * constructing a {@code JSONObject}. Content type/status are set by the caller beforehand,
     * matching the pass-through Servlets that only relay a downstream call's response text.
     */
    public static void writeRaw(HttpServletResponse response, String body) throws IOException {
        try (PrintWriter out = response.getWriter()) {
            out.print(body);
            out.flush();
        }
    }
}
