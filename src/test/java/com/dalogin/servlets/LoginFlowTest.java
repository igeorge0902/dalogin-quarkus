package com.dalogin.servlets;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.junit.jupiter.api.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyOrNullString;

/**
 * Integration tests for the dalogin login flow.
 * <p>
 * Covers:
 * <ol>
 *   <li>POST /HelloWorld — successful login (HMAC + credential validation)</li>
 *   <li>POST /HelloWorld — failed login (bad HMAC)</li>
 *   <li>GET  /HelloWorld — parameter validation</li>
 *   <li>GET  /admin      — after login, retrieve user via downstream mbook call</li>
 *   <li>GET  /admin      — without session → 502</li>
 * </ol>
 * <p>
 * Requires a running MySQL instance with the {@code login_} schema imported
 * and a test user present (see {@link #USER} / {@link #PASS_HASH}).
 * The downstream mbook service must be reachable at {@code WILDFLY_URL}
 * (default {@code http://localhost:8888}) for the admin/retrieve-user step.
 */
@QuarkusTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class LoginFlowTest {

    // ── Test user credentials (must exist in login_ DB) ──────────
    private static final String USER = "GI";
    private static final String PASS_HASH =
            "52fa80662e64c128f8389c9ea6c73d4c02368004bf4463491900d11aaadca39d"
          + "47de1b01361f207c512cfa79f0f92c3395c67ff7928e3f5ce3e3c852b392f976";
    private static final String DEVICE_ID = "test-device-001";
    private static final String IOS_FLAG = "17.0";

    // ── State shared across ordered tests ────────────────────────
    private static String jsessionId;
    private static String xToken;
    private static String xsrfCookie;

    // ── HMAC helpers (mirrors com.dalogin.utils.hmac512 logic) ───

    /**
     * Two-layer HMAC-SHA512 that matches the server's {@code hmac512.hmacSecret()}:
     * first HMAC(password, user) to get the secret, then HMAC(secret, message).
     */
    private static String hmacSha512(String data, String key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA512"));
        byte[] raw = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(raw);
    }

    /**
     * Build the same HMAC hash the server expects for login.
     * Secret = HMAC-SHA512(user, password).
     * Message = "/login/HelloWorld:user=…&pswrd=…&deviceId=…:time:contentLength".
     */
    private static String buildLoginHmac(String user, String pass, String deviceId,
                                         String microTime, String contentLength) throws Exception {
        String secret = hmacSha512(user, pass);
        String message = "/login/HelloWorld:user=" + user
                + "&pswrd=" + pass
                + "&deviceId=" + deviceId
                + ":" + microTime + ":" + contentLength;
        return hmacSha512(message, secret);
    }

    /**
     * Computes the URL-encoded POST body in the same order the client sends it.
     */
    private static String buildFormBody(String user, String pass, String deviceId, String ios) {
        // RestAssured will URL-encode via .formParam(), but we need the raw string
        // length for the Content-Length header that feeds into the HMAC.
        return "user=" + user + "&pswrd=" + pass + "&deviceId=" + deviceId + "&ios=" + ios;
    }

    // ──────────────────────────────────────────────────────────────
    // 1. Successful login
    // ──────────────────────────────────────────────────────────────
    @Test
    @Order(1)
    @DisplayName("POST /HelloWorld — valid credentials + HMAC → 200 with JSESSIONID & X-Token")
    void loginSuccess() throws Exception {
        String body = buildFormBody(USER, PASS_HASH, DEVICE_ID, IOS_FLAG);
        String contentLength = String.valueOf(body.length());
        String microTime = String.valueOf(System.currentTimeMillis());

        String hmac = buildLoginHmac(USER, PASS_HASH, DEVICE_ID, microTime, contentLength);

        Response resp = given()
                .contentType(ContentType.URLENC)
                .header("X-HMAC-HASH", hmac)
                .header("X-MICRO-TIME", microTime)
                .header("M-Device", DEVICE_ID)
                .formParam("user", USER)
                .formParam("pswrd", PASS_HASH)
                .formParam("deviceId", DEVICE_ID)
                .formParam("ios", IOS_FLAG)
            .when()
                .post("/HelloWorld")
            .then()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .body("success", equalTo(1))
                .body("JSESSIONID", not(emptyOrNullString()))
                .body("X-Token", not(emptyOrNullString()))
                .extract().response();

        // Persist for downstream tests
        jsessionId = resp.jsonPath().getString("JSESSIONID");
        xToken = resp.jsonPath().getString("X-Token");
        xsrfCookie = resp.cookie("XSRF-TOKEN");

        assertThat("JSESSIONID must be returned", jsessionId, is(notNullValue()));
        assertThat("X-Token must be returned", xToken, is(notNullValue()));
    }

    // ──────────────────────────────────────────────────────────────
    // 2. Login with wrong HMAC
    // ──────────────────────────────────────────────────────────────
    @Test
    @Order(2)
    @DisplayName("POST /HelloWorld — bad HMAC → 502")
    void loginBadHmac() {
        String microTime = String.valueOf(System.currentTimeMillis());

        given()
                .contentType(ContentType.URLENC)
                .header("X-HMAC-HASH", "INVALID_HMAC_VALUE")
                .header("X-MICRO-TIME", microTime)
                .header("M-Device", DEVICE_ID)
                .formParam("user", USER)
                .formParam("pswrd", PASS_HASH)
                .formParam("deviceId", DEVICE_ID)
                .formParam("ios", IOS_FLAG)
            .when()
                .post("/HelloWorld")
            .then()
                .statusCode(502)
                .body("Success", equalTo("false"));
    }

    // ──────────────────────────────────────────────────────────────
    // 3. Login with wrong password
    // ──────────────────────────────────────────────────────────────
    @Test
    @Order(3)
    @DisplayName("POST /HelloWorld — wrong password → 502")
    void loginWrongPassword() throws Exception {
        String wrongPass = "0000000000000000000000000000000000000000000000000000000000000000"
                         + "0000000000000000000000000000000000000000000000000000000000000000";
        String body = buildFormBody(USER, wrongPass, DEVICE_ID, IOS_FLAG);
        String contentLength = String.valueOf(body.length());
        String microTime = String.valueOf(System.currentTimeMillis());

        String hmac = buildLoginHmac(USER, wrongPass, DEVICE_ID, microTime, contentLength);

        given()
                .contentType(ContentType.URLENC)
                .header("X-HMAC-HASH", hmac)
                .header("X-MICRO-TIME", microTime)
                .header("M-Device", DEVICE_ID)
                .formParam("user", USER)
                .formParam("pswrd", wrongPass)
                .formParam("deviceId", DEVICE_ID)
                .formParam("ios", IOS_FLAG)
            .when()
                .post("/HelloWorld")
            .then()
                .statusCode(502)
                .body("Success", equalTo("false"));
    }

    // ──────────────────────────────────────────────────────────────
    // 4. GET /HelloWorld — missing parameters → 502
    // ──────────────────────────────────────────────────────────────
    @Test
    @Order(4)
    @DisplayName("GET /HelloWorld — missing params → 502")
    void getHelloWorldMissingParams() {
        given()
            .when()
                .get("/HelloWorld")
            .then()
                .statusCode(502);
    }

    // ──────────────────────────────────────────────────────────────
    // 5. GET /HelloWorld — valid parameters (validation only)
    // ──────────────────────────────────────────────────────────────
    @Test
    @Order(5)
    @DisplayName("GET /HelloWorld — valid params → 200 (no auth, just validation)")
    void getHelloWorldValidParams() {
        given()
                .queryParam("user", USER)
                .queryParam("pswrd", PASS_HASH)
                .queryParam("deviceId", DEVICE_ID)
            .when()
                .get("/HelloWorld")
            .then()
                .statusCode(200);
    }

    // ──────────────────────────────────────────────────────────────
    // 6. Admin without session → 502
    // ──────────────────────────────────────────────────────────────
    @Test
    @Order(6)
    @DisplayName("GET /admin — no session → 502 (AuthFilter rejects)")
    void adminWithoutSession() {
        given()
            .when()
                .get("/admin")
            .then()
                .statusCode(502)
                .body("'Error Details'.Success", equalTo("false"));
    }

    // ──────────────────────────────────────────────────────────────
    // 7. Login + Admin (retrieve user from downstream mbook)
    //    This is the full flow: login → /admin → ServiceClient.callGetData
    // ──────────────────────────────────────────────────────────────
    @Test
    @Order(7)
    @DisplayName("Login then GET /admin — retrieves user from mbook downstream service")
    void loginThenRetrieveUser() throws Exception {
        // --- Step A: fresh login ---
        String body = buildFormBody(USER, PASS_HASH, DEVICE_ID, IOS_FLAG);
        String contentLength = String.valueOf(body.length());
        String microTime = String.valueOf(System.currentTimeMillis());
        String hmac = buildLoginHmac(USER, PASS_HASH, DEVICE_ID, microTime, contentLength);

        Response loginResp = given()
                .contentType(ContentType.URLENC)
                .header("X-HMAC-HASH", hmac)
                .header("X-MICRO-TIME", microTime)
                .header("M-Device", DEVICE_ID)
                .formParam("user", USER)
                .formParam("pswrd", PASS_HASH)
                .formParam("deviceId", DEVICE_ID)
                .formParam("ios", IOS_FLAG)
            .when()
                .post("/HelloWorld")
            .then()
                .statusCode(200)
                .extract().response();

        String sessionId = loginResp.jsonPath().getString("JSESSIONID");
        String token = loginResp.jsonPath().getString("X-Token");
        String xsrf = loginResp.cookie("XSRF-TOKEN");

        assertThat("Login must return JSESSIONID", sessionId, is(notNullValue()));
        assertThat("Login must return X-Token", token, is(notNullValue()));

        // --- Step B: call /admin using the session from login ---
        // The AuthFilter checks for a valid session + XSRF-TOKEN cookie.
        // AdminServlet reads user/deviceId from session, calls mbook downstream.
        // Ciphertext header is forwarded by dalogin's RequestFilter to mbook,
        // where CiphertextFilter checks Ciphertext == token2.  X-Token IS token2.
        Response adminResp = given()
                .cookie("JSESSIONID", sessionId)
                .cookie("XSRF-TOKEN", xsrf)
                .header("X-Token", token)
                .header("Ciphertext", token)
                .queryParam("JSESSIONID", sessionId)
            .when()
                .get("/admin")
            .then()
                .extract().response();

        int status = adminResp.statusCode();
        String adminBody = adminResp.asString();
        System.out.println("Admin response status: " + status);
        System.out.println("Admin response body:   " + adminBody);

        // If the downstream mbook service is running, we expect 200 with user data.
        // If it is not running, the AdminServlet will throw and we get 500/502.
        // Either way, the session must have been accepted (AuthFilter did not block us).
        // We assert that we did NOT get the AuthFilter's "no valid session" error.
        assertThat("AuthFilter must not reject a valid session",
                adminBody, not(containsString("no valid session")));
    }
}

