package com.dalogin.filters;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;

import java.io.IOException;

public class CORSFilter implements Filter {
    private static Logger log = Logger.getLogger(Logger.class.getName());

    public void destroy() {
    }

    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws ServletException, IOException {
        HttpServletResponse httpResp = (HttpServletResponse) resp;
        // This is a cross-domain request, add headers allowing access
        httpResp.setHeader("Access-Control-Allow-Headers", "X-Requested-With, X-Token");
        httpResp.setHeader("Access-Control-Expose-Headers", "X-Token");
        httpResp.setHeader("Access-Control-Allow-Origin", "https://milo.crabdance.com");
        httpResp.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE");
        httpResp.setHeader("Access-Control-Max-Age", "3600");
        log.info("CORS headers have been set.");
        chain.doFilter(req, resp);
    }

    public void init(FilterConfig config) throws ServletException {
    }
}