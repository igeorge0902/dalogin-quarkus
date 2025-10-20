package com.dalogin.listeners;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpSessionBindingEvent;
import jakarta.servlet.http.HttpSessionBindingListener;

public class SessionBindingListener implements HttpSessionBindingListener {
    ServletContext context;

    /**
     * @param context
     */
    public SessionBindingListener(ServletContext context) {
        this.context = context;
    }

    /**
     *
     */
    public void valueBound(HttpSessionBindingEvent event) {
        context.log("The value bound is " + event.getName());
    }

    /**
     *
     */
    public void valueUnbound(HttpSessionBindingEvent event) {
        context.log("The value unbound is " + event.getName());
    }
}