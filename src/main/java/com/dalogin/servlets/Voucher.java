package com.dalogin.servlets;
/**
 * @author George Gaspar
 * @email: igeorge1982@gmail.com
 * @Year: 2015
 */

import com.dalogin.persistence.voucher.VoucherManager;
import com.dalogin.servlets.responsemap.VoucherResponses;
import jakarta.inject.Inject;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jboss.logging.Logger;

import java.io.IOException;

@WebServlet(urlPatterns = "/voucher", name = "Voucher")
public class Voucher extends HttpServlet {
    /**
     *
     */
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(Voucher.class);

    @Inject
    VoucherManager voucherManager;

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String servletName = getServletName();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        log.debugf("HTTP request started: servlet=%s, method=%s, uri=%s", servletName, method, uri);
        try {
        // Set response content type
        response.setContentType("application/json");
        try {
            // Actual logic goes here.
            String voucher = request.getParameter("voucher");
            if (voucher != null && voucherManager.checkVoucher(voucher)) {
                VoucherResponses.ok(response);
            } else {
                VoucherResponses.preconditionFailed(response);
            }
        } catch (Exception e) {
            VoucherResponses.badGateway(response);
        }
        } finally {
            log.debugf("HTTP request completed: method=%s, uri=%s, status=%d", method, uri, response.getStatus());
        }
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String servletName = getServletName();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        log.debugf("HTTP request started: servlet=%s, method=%s, uri=%s", servletName, method, uri);
        try {
        // Set response content type
        response.setContentType("text/html");
        try {
            String voucher = request.getParameter("voucher");
            if (voucher.trim().isEmpty()) {
                VoucherResponses.badGateway(response);
            }
        } catch (Exception e) {
            VoucherResponses.badGateway(response);
        }
        } finally {
            log.debugf("HTTP request completed: method=%s, uri=%s, status=%d", method, uri, response.getStatus());
        }
    }
}
