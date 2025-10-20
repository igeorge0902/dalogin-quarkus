package com.dalogin.utils;

import java.security.MessageDigest;

public class sha512 {
    private static volatile String text;

    public static void main(String[] args) throws Exception {
        String s = hmac512.getPass_ForgetPSW_Hmac512("gi@gi.com", "52fa80662e64c128f8389c9ea6c73d4c02368004bf4463491900d11aaadca39d47de1b01361f207c512cfa79f0f92c3395c67ff7928e3f5ce3e3c852b392f976", "661503139a7cba2bb360d75a622d71e5d957db6028495eed92034bc957053838895c32cfbc11064e010796f4af7b5da4861e2fef479661c8f3f86a6cb248ab85", "7501012353736560292487537365900144024", "1489969532521", "328");
        String password = "4Tn";
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(password.getBytes());
        byte byteData[] = md.digest();
        //convert the byte to hex format method 1
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < byteData.length; i++) {
            sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
        }
        System.out.println("Hex format : " + sb.toString());
        //convert the byte to hex format method 2
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < byteData.length; i++) {
            String hex = Integer.toHexString(0xff & byteData[i]);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        System.out.println("Hex format : " + hexString.toString());
        System.out.println("hmac : " + s);
    }

    /**
     * Returns the text hashed with SHA-512 algorithm.
     *
     * @param email_
     * @return hashedText
     * <br>
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#MessageDigest">Java Cryptography Architecture
     * Standard Algorithm Name Documentation for JDK 8</a>
     */
    public static String string_hash(String text_) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(text_.getBytes());
            byte byteData[] = md.digest();
            //convert the byte to hex format method 2
            StringBuffer hexString = new StringBuffer();
            for (int i = 0; i < byteData.length; i++) {
                String hex = Integer.toHexString(0xff & byteData[i]);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            text = hexString.toString();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return text;
    }
}