package com.dalogin;

public class SystemConstants {

    public static String getServiceUrl() {
        return System.getenv().getOrDefault("WILDFLY_URL", "http://localhost:8888");
    }
}
