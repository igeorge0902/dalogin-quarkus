package com.dalogin.filters;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jboss.logging.Logger;

import java.io.IOException;

/**
 * CORS response-header filter.
 *
 * <p><strong>Currently NOT registered</strong> (no {@code @WebFilter}, not in {@code web.xml}).
 * CORS headers are set at the Apache reverse-proxy layer ({@code proxy.conf} in the
 * {@code apache-config} ConfigMap). This class is kept for reference / fallback if the
 * Apache layer is ever removed.
 *
 * <p>If activated, ensure the Apache {@code <IfModule mod_headers.c>} CORS directives are
 * removed to avoid duplicate headers.
 */
public class CORSFilter implements Filter {
    private static final Logger log = Logger.getLogger(CORSFilter.class);

    public void destroy() {
    }

    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws ServletException, IOException {
        HttpServletRequest httpReq = (HttpServletRequest) req;
        HttpServletResponse httpResp = (HttpServletResponse) resp;
        String method = httpReq.getMethod();
        String uri = httpReq.getRequestURI();
        log.debugf("HTTP request started: filter=%s, method=%s, uri=%s", "CORSFilter", method, uri);
        try {
            httpResp.setHeader("Access-Control-Allow-Origin", "https://milo.crabdance.com");
            httpResp.setHeader("Access-Control-Expose-Headers", "X-Token, APIKEY");
            httpResp.setHeader("Access-Control-Max-Age", "1800");
            httpResp.setHeader("Access-Control-Allow-Headers",
                    "Content-Type, Accept, Authorization, Origin, X-Requested-With, X-Token, X-HMAC-HASH, X-MICRO-TIME, X-Device, Accept-Encoding");
            httpResp.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE, PUT");
            log.debug("CORS headers have been set");
            chain.doFilter(req, resp);
        } finally {
            log.debugf("HTTP request completed: method=%s, uri=%s, status=%d", method, uri, httpResp.getStatus());
        }
    }

    public void init(FilterConfig config) throws ServletException {
    }
}
