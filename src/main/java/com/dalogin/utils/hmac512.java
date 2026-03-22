package com.dalogin.utils;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class hmac512 {
    private static final Logger log = Logger.getLogger(Logger.class.getName());

    /**
     * Returns the final hmac string to validate the client request. The method parameters will form a string that will be hashed to match against what was received from the request.
     */
    public static String getLoginHmac512(String user, String pswrd, String deviceId, String time, String contentLength) {
        String secret = hmacSecret(user, pswrd);
        try {
            String message = "/login/HelloWorld:user=" + user + "&pswrd=" + pswrd + "&deviceId=" + deviceId + ":" + time + ":" + contentLength;
            Mac HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA512");
            HMAC.init(secret_key);
            return new String(Base64.encodeBase64(HMAC.doFinal(message.getBytes())));
        } catch (Exception e) {
            log.error("1 Error");
        }
        return null;
    }

    /**
     * Returns the final hmac string to validate the client request. The method parameters will form a string that will be hashed to match against what was received.
     */
    public static String getRegHmac512(String user, String email, String pswrd, String deviceId, String voucher, String time, String contentLength) {
        String secret = hmacSecret(user, pswrd);
        try {
            String message = "/login/register:user=" + user + "&email=" + email + "&pswrd=" + pswrd + "&deviceId=" + deviceId + "&voucher_=" + voucher + ":" + time + ":" + contentLength;
            Mac HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA512");
            HMAC.init(secret_key);
            return new String(Base64.encodeBase64(HMAC.doFinal(message.getBytes())));
        } catch (Exception e) {
            log.error("1 Error");
        }
        return null;
    }

    /**
     * Returns the final hmac string to validate the client request. The method parameters will form a string that will be hashed to match against what was received.
     */
    public static String getRegWithoutVoucherHmac512(String user, String email, String pswrd, String deviceId, String time, String contentLength) {
        String secret = hmacSecret(user, pswrd);
        try {
            String message = "/login/register:user=" + user + "&email=" + email + "&pswrd=" + pswrd + "&deviceId=" + deviceId + ":" + time + ":" + contentLength;
            Mac HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA512");
            HMAC.init(secret_key);
            return new String(Base64.encodeBase64(HMAC.doFinal(message.getBytes())));
        } catch (Exception e) {
            log.error("1 Error");
        }
        return null;
    }

    /**
     * Returns the final hmac string to validate the client request. The method parameters will form a string that will be hashed to match against what was received.
     */
    public static String getEmail_ForgetPSW_Hmac512(String email, String deviceId, String time, String contentLength) {
        String hashed_email = sha512.string_hash(email);
        String secret = hmacSecret(email, hashed_email);
        try {
            String message = "/login/forgotPSw:email=" + email + "&deviceId=" + deviceId + ":" + time + ":" + contentLength;
            Mac HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA512");
            HMAC.init(secret_key);
            return new String(Base64.encodeBase64(HMAC.doFinal(message.getBytes())));
        } catch (Exception e) {
            log.error("1 Error");
        }
        return null;
    }

    /**
     * Returns the final hmac string to validate the client request. The method parameters will form a string that will be hashed to match against what was received.
     */
    public static String getCode_ForgetPSW_Hmac512(String email, String code, String deviceId, String time, String contentLength) {
        String hashed_code = sha512.string_hash(code);
        String secret = hmacSecret(email, hashed_code);
        try {
            String message = "/login/forgotPSwCode:email=" + email + "&cC=" + hashed_code + "&deviceId=" + deviceId + ":" + time + ":" + contentLength;
            Mac HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA512");
            HMAC.init(secret_key);
            return new String(Base64.encodeBase64(HMAC.doFinal(message.getBytes())));
        } catch (Exception e) {
            log.error("1 Error");
        }
        return null;
    }

    /**
     * Returns the final hmac string to validate the client request. The method parameters will form a string that will be hashed to match against what was received.
     */
    public static String getPass_ForgetPSW_Hmac512(String email, String pass, String code, String deviceId, String time, String contentLength) {
        String secret = hmacSecret(email, pass);
        try {
            String message = "/login/forgotPSwNewPSw:email=" + email + "&cC=" + code + "&pass=" + pass + "&deviceId=" + deviceId + ":" + time + ":" + contentLength;
            Mac HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA512");
            HMAC.init(secret_key);
            return new String(Base64.encodeBase64(HMAC.doFinal(message.getBytes())));
        } catch (Exception e) {
            log.error("1 Error");
        }
        return null;
    }

    /**
     * Generate hmacSecret as payload for hmac512 hash.
     */
    private static String hmacSecret(String message, String secret) {
        try {
            Mac HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA512");
            HMAC.init(secret_key);
            return new String(Base64.encodeBase64(HMAC.doFinal(message.getBytes())));
        } catch (Exception e) {
            log.error(e.getCause().toString());
        }
        return null;
    }
}
