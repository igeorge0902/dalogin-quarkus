package com.dalogin.persistence.devicesession;

/**
 * Token pair read back from {@code get_token2}: the rotated credential token and its rotation
 * time, used both for cookie/header issuance and for the client-side XSRF token derivation.
 */
public record SessionTokens(String token, String time) {
}
