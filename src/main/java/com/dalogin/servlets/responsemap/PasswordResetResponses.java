package com.dalogin.servlets.responsemap;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.json.JSONObject;

import java.io.IOException;

import static com.dalogin.servlets.support.ServletResponses.writeJson;

/**
 * Shared response operations for the password-reset family, used only where the wire contract is
 * byte-identical across {@code ChangePassword}, {@code ChangePasswordCode}, and
 * {@code ChangePasswordNewPassword}.
 */
public final class PasswordResetResponses {

    private PasswordResetResponses() {
    }

    /** {@code ChangePasswordCode}/{@code ChangePasswordNewPassword}: missing confirmation code. */
    public static void missingConfirmationCode(HttpServletResponse response) throws IOException {
        writeJson(response, HttpServletResponse.SC_OK, new JSONObject()
                .put("Session", "raked")
                .put("Success", "false")
                .put("Error", "no confirmationCode!"));
    }

    /** {@code ChangePasswordCode}/{@code ChangePasswordNewPassword}: code validation succeeded. */
    public static void codeValid(HttpServletResponse response) throws IOException {
        writeJson(response, HttpServletResponse.SC_OK, new JSONObject()
                .put("Success", "true")
                .put("Code", "isValid"));
    }

    /** {@code ChangePassword}/{@code ChangePasswordCode}/{@code ChangePasswordNewPassword}: validation failed. */
    public static void validationFailed(HttpServletResponse response) throws IOException {
        writeJson(response, HttpServletResponse.SC_BAD_GATEWAY, new JSONObject().put("Success", "false"));
    }

    /** {@code ChangePassword}: missing email parameter. */
    public static void missingEmail(HttpServletResponse response) throws IOException {
        writeJson(response, HttpServletResponse.SC_OK, new JSONObject()
                .put("Session", "raked")
                .put("Success", "false")
                .put("Error", "no email!"));
    }

    /** {@code ChangePassword}: forgot-password token was the "ilt" sentinel. */
    public static void alreadyRequested(HttpServletResponse response) throws IOException {
        writeJson(response, HttpServletResponse.SC_OK, new JSONObject()
                .put("Session", "raked")
                .put("Success", "false"));
    }

    /** {@code ChangePassword}: forgot-password request succeeded. */
    public static void requestSucceeded(HttpServletResponse response, String encryptedToken, String code)
            throws IOException {
        Cookie cookie = new Cookie("XSRF-TOKEN", encryptedToken);
        cookie.setSecure(true);
        cookie.setMaxAge(1800);
        response.addCookie(cookie);
        writeJson(response, HttpServletResponse.SC_OK, new JSONObject()
                .put("Success", "true")
                .put("Code", code));
    }

    /** {@code ChangePasswordNewPassword}: password shorter than the minimum length. */
    public static void passwordTooShort(HttpServletResponse response) throws IOException {
        writeJson(response, HttpServletResponse.SC_OK, new JSONObject()
                .put("Session", "raked")
                .put("Success", "false")
                .put("Error", "passWord is too short!"));
    }
}
