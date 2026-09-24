package com.dalogin.client.filter;

import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientResponseContext;
import jakarta.ws.rs.client.ClientResponseFilter;
import org.jboss.logging.Logger;

import java.io.IOException;

public class ClientCallResponseFilter implements ClientResponseFilter {

    private static final Logger LOG = Logger.getLogger("LOG-HTTP-CLIENT");

    @Override
    public void filter(ClientRequestContext requestContext, ClientResponseContext responseContext) throws IOException {
        int status = responseContext.getStatus();

        if (status >= 500) {
            LOG.errorf(
                    "event=OUTBOUND_ERROR method=%s uri=%s path=%s status=%d",
                    requestContext.getMethod(),
                    requestContext.getUri(),
                    requestContext.getUri().getPath(),
                    status
            );
        } else if (status >= 400) {
            LOG.warnf(
                    "event=OUTBOUND_END method=%s uri=%s path=%s status=%d",
                    requestContext.getMethod(),
                    requestContext.getUri(),
                    requestContext.getUri().getPath(),
                    status
            );
        } else {
            LOG.debugf(
                    "event=OUTBOUND_END method=%s uri=%s path=%s status=%d",
                    requestContext.getMethod(),
                    requestContext.getUri(),
                    requestContext.getUri().getPath(),
                    status
            );
        }
    }
}

