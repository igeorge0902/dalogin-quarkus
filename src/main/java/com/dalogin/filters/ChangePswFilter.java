package com.dalogin.filters;

import com.dalogin.SQLAccess;
import com.dalogin.utils.AesUtil;
import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.util.List;

@WebFilter(servletNames = {"ChangePasswordNewPassword"})
public class ChangePswFilter implements Filter {
    private static final int KEYSIZE = 128;
    private static final int ITERATIONCOUNT = 1000;
    private static final String SALT = "3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55";
    private static final String IV = "F27D5C9927726BCEFE7510B1BDD3D137";
    private volatile static List<String> cC;
    private static AesUtil aesUtil;
    private volatile static String encrypted_token;
    private volatile static String email;
    private static Logger log = Logger.getLogger(Logger.class.getName());
    private ServletContext context;

    public void init(FilterConfig fConfig) throws ServletException {
        this.context = fConfig.getServletContext();
        this.context.log("AuthenticationFilter initialized");
        aesUtil = new AesUtil(KEYSIZE, ITERATIONCOUNT);
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        email = request.getParameter("email");
        // Set the response message's MIME type
        response.setContentType("text/html;charset=UTF-8");
        // retrieve email which requested the password reset
        try {
            cC = SQLAccess.getForgotPswConfirmationCode(email, context);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        encrypted_token = aesUtil.encrypt(SALT, IV, cC.get(1), cC.get(0));
        Cookie[] cookies = req.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equalsIgnoreCase("XSRF-TOKEN")) {
                    String actualToken = cookie.getValue().trim();
                    String encrypted_token_ = "";
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
    }

    public void destroy() {
        //close any resources here
    }
}