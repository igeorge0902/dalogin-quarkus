package com.dalogin.client.service;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/rest")
public interface Device {
    @GET
    @Path("/device/{uuid}")
    @Produces({MediaType.APPLICATION_JSON})
    Response getData(@PathParam("uuid") String uuid);
}
