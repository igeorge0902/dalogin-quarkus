package com.dalogin.servlets.responsemap;

/**
 * Values needed to publish a successful login response: cookies, header, and JSON body.
 */
public record LoginSuccess(
        String contextPath,
        int maxAge,
        String sessionId,
        String token,
        String xsrfToken,
        boolean mobileClient
) {
}
