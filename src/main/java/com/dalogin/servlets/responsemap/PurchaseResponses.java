package com.dalogin.servlets.responsemap;

import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

import static com.dalogin.servlets.support.ServletResponses.writeRaw;

/**
 * Named response operations for {@code ManagePurchases}, {@code GetAllPurchases}, and
 * {@code CheckOut}: each streams an already-serialized downstream response body.
 */
public final class PurchaseResponses {

    private PurchaseResponses() {
    }

    public static void downstreamBody(HttpServletResponse response, String body) throws IOException {
        writeRaw(response, body);
    }

    public static void missingAuthenticationToken(HttpServletResponse response) throws IOException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing authentication token");
    }
}
