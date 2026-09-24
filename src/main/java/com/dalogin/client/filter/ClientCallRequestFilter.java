package com.dalogin.client.filter;

import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;
import org.jboss.logging.Logger;

import java.io.IOException;

public class ClientCallRequestFilter implements ClientRequestFilter {

    private static final Logger LOG = Logger.getLogger("LOG-HTTP-CLIENT");

    @Override
    public void filter(ClientRequestContext requestContext) throws IOException {
        requestContext.setProperty("call.start.ms", System.currentTimeMillis());
        LOG.debugf(
                "event=OUTBOUND_START method=%s uri=%s path=%s",
                requestContext.getMethod(),
                requestContext.getUri(),
                requestContext.getUri().getPath()
        );
    }
}

