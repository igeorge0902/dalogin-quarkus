package com.dalogin;

public class SystemConstants {

    /** Database catalog derived from the JDBC URL (last path segment). */
    public static final String DB_CATALOG = extractCatalog();

    public static String getServiceUrl() {
        return System.getenv().getOrDefault("WILDFLY_URL", "http://localhost:8888");
    }

    private static String extractCatalog() {
        String url = System.getenv().getOrDefault("DB_URL", "jdbc:mysql://localhost:3306/login_");
        int lastSlash = url.lastIndexOf('/');
        return (lastSlash >= 0 && lastSlash < url.length() - 1)
                ? url.substring(lastSlash + 1)
                : "login_";
    }
}
