package com.dalogin.servlets.responsemap;

/**
 * Values needed to publish a successful {@code RegistrationWithoutVoucher} response. {@code
 * token2} is deliberately the whole two-element list (not just the token) to preserve the
 * existing {@code X-Token} JSON-array quirk in the response body.
 */
public record RegistrationWithoutVoucherSuccess(
        int maxAge,
        String sessionId,
        java.util.List<String> token2,
        String xsrfToken
) {
}
