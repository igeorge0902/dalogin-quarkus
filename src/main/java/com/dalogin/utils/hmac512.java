package com.dalogin.utils;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class hmac512 {
    /**
     *
     */
    private static volatile String hmachHash;
    /**
     *
     */
    private static volatile String strEncoded;
    /**
     *
     */
    private static volatile String secret_;
    /**
     *
     */
    private static volatile String message_;
    /**
     *
     */
    private static volatile String hashed_email;
    /**
     *
     */
    private static volatile String hashed_code;
    private static Logger log = Logger.getLogger(Logger.class.getName());

    /**
     * Returns the final hmac string to validate the client request. The method parameters will form a string that will be hashed to match against what was received from the request.
     *
     * @param user
     * @param pswrd
     * @param deviceId
     * @param time
     * @param contentLength
     * @return <br>
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#MessageDigest">Java Cryptography Architecture
     * Standard Algorithm Name Documentation for JDK 8</a>
     */
    public static String getLoginHmac512(String user, String pswrd, String deviceId, String time, String contentLength) {
        secret_ = hmacSecret(user, pswrd);
        try {
            //TODO: match full URL with hostname (absolute path),
            // and more generated constants, like the url that we'll use for hash only
            message_ = "/login/HelloWorld:user=" + user + "&pswrd=" + pswrd + "&deviceId=" + deviceId + ":" + time + ":" + contentLength;
            Mac HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec secret_key = new SecretKeySpec(secret_.getBytes(), "HmacSHA512");
            HMAC.init(secret_key);
//     hmachHash = Base64.encodeBase64String(HMAC.doFinal(message_.getBytes()));
            hmachHash = new String(Base64.encodeBase64(HMAC.doFinal(message_.getBytes())));
        } catch (Exception e) {
            log.error("1 Error");
        }
        return hmachHash;
    }

    /**
     * Returns the final hmac string to validate the client request. The method parameters will form a string that will be hashed to match against what was received.
     *
     * @param user
     * @param email
     * @param pswrd
     * @param deviceId
     * @param voucher
     * @param time
     * @param contentLength
     * @return <br>
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#MessageDigest">Java Cryptography Architecture
     * Standard Algorithm Name Documentation for JDK 8</a>
     */
    public static String getRegHmac512(String user, String email, String pswrd, String deviceId, String voucher, String time, String contentLength) {
        secret_ = hmacSecret(user, pswrd);
        try {
            //TODO: match full URL with hostname (absolute path),
            // and more generated constants, like the url that we'll use for hash only
            message_ = "/login/register:user=" + user + "&email=" + email + "&pswrd=" + pswrd + "&deviceId=" + deviceId + "&voucher_=" + voucher + ":" + time + ":" + contentLength;
            Mac HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec secret_key = new SecretKeySpec(secret_.getBytes(), "HmacSHA512");
            HMAC.init(secret_key);
//     hmachHash = Base64.encodeBase64String(HMAC.doFinal(message_.getBytes()));
            hmachHash = new String(Base64.encodeBase64(HMAC.doFinal(message_.getBytes())));
        } catch (Exception e) {
            log.error("1 Error");
        }
        return hmachHash;
    }

    /**
     * Returns the final hmac string to validate the client request. The method parameters will form a string that will be hashed to match against what was received.
     *
     * @param user
     * @param email
     * @param pswrd
     * @param deviceId
     * @param time
     * @param contentLength
     * @return <br>
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#MessageDigest">Java Cryptography Architecture
     * Standard Algorithm Name Documentation for JDK 8</a>
     */
    public static String getRegWithoutVoucherHmac512(String user, String email, String pswrd, String deviceId, String time, String contentLength) {
        secret_ = hmacSecret(user, pswrd);
        try {
            //TODO: match full URL with hostname (absolute path),
            // and more generated constants, like the url that we'll use for hash only
            message_ = "/login/register:user=" + user + "&email=" + email + "&pswrd=" + pswrd + "&deviceId=" + deviceId + ":" + time + ":" + contentLength;
            Mac HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec secret_key = new SecretKeySpec(secret_.getBytes(), "HmacSHA512");
            HMAC.init(secret_key);
//     hmachHash = Base64.encodeBase64String(HMAC.doFinal(message_.getBytes()));
            hmachHash = new String(Base64.encodeBase64(HMAC.doFinal(message_.getBytes())));
        } catch (Exception e) {
            log.error("1 Error");
        }
        return hmachHash;
    }

    /**
     * Returns the final hmac string to validate the client request. The method parameters will form a string that will be hashed to match against what was received.
     *
     * @param email
     * @param deviceId
     * @param time
     * @param contentLength
     * @return <br>
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#MessageDigest">Java Cryptography Architecture
     * Standard Algorithm Name Documentation for JDK 8</a>
     */
    public static String getEmail_ForgetPSW_Hmac512(String email, String deviceId, String time, String contentLength) {
        hashed_email = sha512.string_hash(email);
        secret_ = hmacSecret(email, hashed_email);
        try {
            //TODO: match full URL with hostname (absolute path),
            // and more generated constants, like the url that we'll use for hash only
            message_ = "/login/forgotPSw:email=" + email + "&deviceId=" + deviceId + ":" + time + ":" + contentLength;
            Mac HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec secret_key = new SecretKeySpec(secret_.getBytes(), "HmacSHA512");
            HMAC.init(secret_key);
//     hmachHash = Base64.encodeBase64String(HMAC.doFinal(message_.getBytes()));
            hmachHash = new String(Base64.encodeBase64(HMAC.doFinal(message_.getBytes())));
        } catch (Exception e) {
            log.error("1 Error");
        }
        return hmachHash;
    }

    /**
     * Returns the final hmac string to validate the client request. The method parameters will form a string that will be hashed to match against what was received.
     *
     * @param email
     * @param code
     * @param deviceId
     * @param time
     * @param contentLength
     * @return <br>
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#MessageDigest">Java Cryptography Architecture
     * Standard Algorithm Name Documentation for JDK 8</a>
     */
    public static String getCode_ForgetPSW_Hmac512(String email, String code, String deviceId, String time, String contentLength) {
        hashed_code = sha512.string_hash(code);
        secret_ = hmacSecret(email, hashed_code);
        try {
            //TODO: match full URL with hostname (absolute path),
            // and more generated constants, like the url that we'll use for hash only
            message_ = "/login/forgotPSwCode:email=" + email + "&cC=" + hashed_code + "&deviceId=" + deviceId + ":" + time + ":" + contentLength;
            Mac HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec secret_key = new SecretKeySpec(secret_.getBytes(), "HmacSHA512");
            HMAC.init(secret_key);
//     hmachHash = Base64.encodeBase64String(HMAC.doFinal(message_.getBytes()));
            hmachHash = new String(Base64.encodeBase64(HMAC.doFinal(message_.getBytes())));
        } catch (Exception e) {
            log.error("1 Error");
        }
        return hmachHash;
    }

    /**
     * Returns the final hmac string to validate the client request. The method parameters will form a string that will be hashed to match against what was received.
     *
     * @param email
     * @param pass
     * @param code
     * @param deviceId
     * @param time
     * @param contentLength
     * @return <br>
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#MessageDigest">Java Cryptography Architecture
     * Standard Algorithm Name Documentation for JDK 8</a>
     */
    public static String getPass_ForgetPSW_Hmac512(String email, String pass, String code, String deviceId, String time, String contentLength) {
        //hashed_code = sha512.string_hash(code);
        secret_ = hmacSecret(email, pass);
        try {
            //TODO: match full URL with hostname (absolute path),
            // and more generated constants, like the url that we'll use for hash only
            message_ = "/login/forgotPSwNewPSw:email=" + email + "&cC=" + code + "&pass=" + pass + "&deviceId=" + deviceId + ":" + time + ":" + contentLength;
            Mac HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec secret_key = new SecretKeySpec(secret_.getBytes(), "HmacSHA512");
            HMAC.init(secret_key);
//     hmachHash = Base64.encodeBase64String(HMAC.doFinal(message_.getBytes()));
            hmachHash = new String(Base64.encodeBase64(HMAC.doFinal(message_.getBytes())));
        } catch (Exception e) {
            log.error("1 Error");
        }
        return hmachHash;
    }

    /**
     * Generate hmacSecret as payload for hmac512 hash.
     *
     * @param message
     * @param secret
     * @return <br>
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#MessageDigest">Java Cryptography Architecture
     * Standard Algorithm Name Documentation for JDK 8</a>
     */
    private static String hmacSecret(String message, String secret) {
        try {
            Mac HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA512");
            HMAC.init(secret_key);
//		     hmacSecret_ = Base64.encodeBase64String(HMAC.doFinal(message.getBytes()));
            strEncoded = new String(Base64.encodeBase64(HMAC.doFinal(message.getBytes())));
        } catch (Exception e) {
            log.error(e.getCause().toString());
        }
        return strEncoded;
    }
}
