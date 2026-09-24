package com.dalogin.servlets.responsemap;

import jakarta.servlet.http.HttpServletResponse;
import org.json.JSONObject;

import java.io.IOException;

import static com.dalogin.servlets.support.ServletResponses.writeJson;

/** Named response operations for {@code Voucher}. */
public final class VoucherResponses {

    private VoucherResponses() {
    }

    public static void ok(HttpServletResponse response) throws IOException {
        writeJson(response, HttpServletResponse.SC_OK, new JSONObject()
                .put("Voucher", "Okay")
                .put("Success", "true"));
    }

    public static void preconditionFailed(HttpServletResponse response) throws IOException {
        response.sendError(HttpServletResponse.SC_PRECONDITION_FAILED);
    }

    public static void badGateway(HttpServletResponse response) throws IOException {
        response.sendError(HttpServletResponse.SC_BAD_GATEWAY);
    }
}
