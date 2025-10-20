package com.dalogin.client.service;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/rest")
public interface User {
    @GET
    @Path("/user/{user}/{token1}")
    @Produces({MediaType.APPLICATION_JSON})
    Response getData(@PathParam("user") String user, @PathParam("token1") String token1);
}
