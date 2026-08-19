package com.dalogin.filters;

import com.dalogin.SQLAccess;
import com.dalogin.utils.AesUtil;
import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.util.List;

@WebFilter(servletNames = {"ChangePasswordNewPassword"})
public class ChangePswFilter implements Filter {
    private static final int KEYSIZE = 128;
    private static final int ITERATIONCOUNT = 1000;
    private static final String SALT = "3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55";
    private static final String IV = "F27D5C9927726BCEFE7510B1BDD3D137";
    private static final Logger log = Logger.getLogger(ChangePswFilter.class);
    private AesUtil aesUtil;
    private ServletContext context;

    public void init(FilterConfig fConfig) throws ServletException {
        this.context = fConfig.getServletContext();
        log.debug("ChangePswFilter initialized");
        aesUtil = new AesUtil(KEYSIZE, ITERATIONCOUNT);
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        String method = req.getMethod();
        String uri = req.getRequestURI();
        log.debugf("HTTP request started: filter=%s, method=%s, uri=%s", "ChangePswFilter", method, uri);
        try {
            String email = request.getParameter("email");
            // Set the response message's MIME type
            response.setContentType("text/html;charset=UTF-8");
            // retrieve email which requested the password reset
            List<String> cC;
            try {
                cC = SQLAccess.getForgotPswConfirmationCode(email, context);
            } catch (Exception e) {
                log.error("Unable to retrieve confirmation code for password reset", e);
                return;
            }
            String encrypted_token = aesUtil.encrypt(SALT, IV, cC.get(1), cC.get(0));
            Cookie[] cookies = req.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (cookie.getName().equalsIgnoreCase("XSRF-TOKEN")) {
                        String actualToken = cookie.getValue().trim();
                        String encrypted_token_;
                        String token = encrypted_token.trim();
                        int l = token.length();
                        if (token.endsWith("=")) {
                            encrypted_token_ = token.substring(0, l - 1);
                        } else {
                            encrypted_token_ = encrypted_token;
                        }
                        if (!actualToken.equals(encrypted_token_)) {
                            throw new ServletException("There is no valid XSRF-TOKEN");
                        } else {
                            // pass the request along the filter chain
                            chain.doFilter(request, response);
                        }
                    }
                }
            }
        } finally {
            log.debugf("HTTP request completed: method=%s, uri=%s, status=%d", method, uri, resp.getStatus());
        }
    }

    public void destroy() {
        //close any resources here
    }
}
