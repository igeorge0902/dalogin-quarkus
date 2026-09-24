package com.dalogin.servlets.responsemap;

/**
 * Values needed to publish a successful {@code Registration} response.
 */
public record RegistrationSuccess(
        String contextPath,
        int maxAge,
        String sessionId,
        String token,
        String xsrfToken
) {
}
