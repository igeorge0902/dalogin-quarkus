package com.dalogin;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.JSONObject;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;

@WebServlet("/ExceptionHandler")
public class ExceptionHandler extends HttpServlet {
    private static final long serialVersionUID = 1L;

    protected synchronized void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        processError(request, response);
    }

    protected synchronized void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        processError(request, response);
    }

    public synchronized void processError(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Analyze the servlet exception
        Throwable throwable = (Throwable) request.getAttribute("jakarta.servlet.error.exception");
        Integer statusCode = (Integer) request.getAttribute("jakarta.servlet.error.status_code");
        String servletName = (String) request.getAttribute("jakarta.servlet.error.servlet_name");
        String message = (String) request.getAttribute("jakarta.servlet.error.message");
        if (servletName == null) {
            servletName = "Unknown";
        }
        if (message == null) {
            message = "Unknown";
        }
        String requestUri = (String) request.getAttribute("jakarta.servlet.error.request_uri");
        if (requestUri == null) {
            requestUri = "Unknown";
        }
        // Set response content type
        response.setContentType("application/json");
        PrintWriter out = response.getWriter();
        //create Json Object
        JSONObject json = new JSONObject();
        HashMap<String, String> error = new HashMap<>();
        if (statusCode != 500) {
            error.put("Status Code:", statusCode.toString());
            error.put("Requested URI:", requestUri);
        } else {
            error.put("Servlet Name:", servletName);
            error.put("Exception name:", throwable.getClass().getName());
            error.put("Requested URI:", requestUri);
            error.put("Exception Message:", throwable.getMessage());
            error.put("Error Message:", message);
            error.put("Info:", "Check the corresponding server logs!");
        }
        // put some value pairs into the JSON object .
        json.put("Error Details", error);
        // finally output the json string
        out.print(json.toString());
        out.flush();
    }
}
