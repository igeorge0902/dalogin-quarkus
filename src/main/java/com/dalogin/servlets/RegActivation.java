package com.dalogin.servlets;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2015
 */

import com.dalogin.SQLAccess;
import com.dalogin.utils.AesUtil;
import com.dalogin.utils.SendHtmlEmail;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@WebServlet(urlPatterns = "/activation", name = "RegActivation")
public class RegActivation extends HttpServlet {
    private static final long serialVersionUID = -933199811013368066L;
    private static final String SALT = "3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55";
    private static final String IV = "F27D5C9927726BCEFE7510B1BDD3D137";
    private static final String activationToken_ = "G";
    private static final int KEYSIZE = 128;
    private static final int ITERATIONCOUNT = 1000;
    private static final Logger log = Logger.getLogger(Logger.class.getName());

    private AesUtil aesUtil;

    public void init() throws ServletException {
        aesUtil = new AesUtil(KEYSIZE, ITERATIONCOUNT);
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        ServletContext context = session.getServletContext();
        String ciphertext = request.getHeader("Ciphertext");
        if (ciphertext != null) ciphertext = ciphertext.trim();
        StringBuilder sb = new StringBuilder();
        BufferedReader br = request.getReader();
        String str;
        while ((str = br.readLine()) != null) {
            sb.append(str);
        }
        JSONObject jObj = new JSONObject(sb.toString());
        String user = jObj.getString("user");
        String deviceId = jObj.getString("deviceId");
        try {
            List<String> token2 = SQLAccess.getToken2(deviceId, context);
            boolean isValid = token2.get(0).equals(ciphertext);
            if (isValid) {
                List<String> list = SQLAccess.getActivationToken(user, context);
                String token = list.get(0);
                String email = list.get(1);
                // send email for activation
                String scheme = request.getScheme();
                String serverName = request.getServerName();
                String servletContext = context.getContextPath();
                // prepare data
                String activationData = "user=" + user + "&token2=" + token;
                // Construct requesting URL
                StringBuilder url = new StringBuilder();
                url.append(scheme).append("://")
                        .append(serverName).append(servletContext).append("/activation")
                        .append("?").append("activation=").append(aesUtil.encrypt(SALT, IV, activationToken_, activationData));
                SendHtmlEmail.generateAndSendEmail(email, url.toString());
                JSONObject json = new JSONObject();
                json.put("Success", "true");
                json.put("Email was sent to:", email);
                response.setContentType("application/json");
                response.setCharacterEncoding("utf-8");
                response.setStatus(200);
                response.getWriter().write(json.toString());
            } else {
                response.sendError(HttpServletResponse.SC_PRECONDITION_FAILED, "Line 125");
            }
        } catch (Exception e) {
            String error = e.getCause().toString();
            log.info(error);
            JSONObject json = new JSONObject();
            json.put("Error", error);
            response.setContentType("application/json");
            response.setCharacterEncoding("utf-8");
            response.setStatus(502);
            response.getWriter().write(json.toString());
            response.flushBuffer();
        }
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");
        HttpSession session = request.getSession(true);
        ServletContext context = session.getServletContext();
        String parameter = request.getQueryString();
        String[] activationData = parameter.split("=");
        String query = aesUtil.decrypt(SALT, IV, activationToken_, activationData[1]);
        String[] params = query.split("&");
        Map<String, String> queryMap = new HashMap<>();
        String user = "";
        String token2 = "";
        int i = 0;
        Arrays.sort(params);
        for (String param : params) {
            String name = param.split("=")[0];
            String value = param.split("=")[1];
            queryMap.put(name, value);
            i++;
            if (i == 1) {
                token2 = value;
            }
            if (i == 2) {
                user = value;
            }
        }
        //TODO: activate the voucher
        try {
            SQLAccess.activateVoucher(token2, user, context);
        } catch (Exception e) {
            String error = e.getCause().toString();
            log.info(error);
            JSONObject json = new JSONObject();
            json.put("Error", error);
            response.setContentType("application/json");
            response.setCharacterEncoding("utf-8");
            response.setStatus(502);
            response.getWriter().write(json.toString());
            response.flushBuffer();
        }
        session.invalidate();
        PrintWriter out = response.getWriter();
        JSONObject json = new JSONObject();
        JSONArray list = new JSONArray();
        list.put(queryMap);
        json.put("activation", list);
        json.put("Registration:", "active");
        out.print(json.toString());
        out.flush();
    }

    public void destroy() {
        // do nothing.
    }
}
