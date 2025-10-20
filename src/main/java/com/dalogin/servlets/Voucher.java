package com.dalogin.servlets;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2015
 */

import com.dalogin.SQLAccess;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.JSONObject;

import java.io.IOException;
import java.io.PrintWriter;

@WebServlet(urlPatterns = "/voucher", name = "Voucher")
public class Voucher extends HttpServlet {
    /**
     *
     */
    private static final long serialVersionUID = 1L;
    private volatile static String voucher;

    public void init() throws ServletException {
    }

    public synchronized void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String userName = "admin";
        String password = "Tapsihapsi666";
        request.login(userName, password);
    }

    public synchronized void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Set response content type
        response.setContentType("application/json");
        try {
            // Actual logic goes here.
            voucher = request.getParameter("voucher");
            ServletContext context = request.getServletContext();
            if (voucher != null && SQLAccess.checkVoucher(voucher, context)) {
                response.setContentType("application/json");
                response.setCharacterEncoding("utf-8");
                response.setStatus(200);
                PrintWriter out = response.getWriter();
                JSONObject json = new JSONObject();
                json.put("Voucher", "Okay");
                json.put("Success", "true");
                out.print(json.toString());
                out.flush();
            } else {
                response.sendError(HttpServletResponse.SC_PRECONDITION_FAILED);
            }
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_BAD_GATEWAY);
        }
    }

    public synchronized void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        //processRequest(request, response);
        // Set response content type
        response.setContentType("text/html");
        try {
            voucher = request.getParameter("voucher");
            if (voucher.trim().isEmpty()) {
                response.sendError(HttpServletResponse.SC_BAD_GATEWAY);
            }
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_BAD_GATEWAY);
        }
    }

    public void destroy() {
        // do nothing.
    }
}
