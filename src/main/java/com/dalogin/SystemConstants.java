package com.dalogin;

public class SystemConstants {

    public static final String getServiceUrl() {
        String serviceUrl = System.getenv().getOrDefault("WILDFLY_URL", "http://localhost:8888");
        return serviceUrl;
    }
}
