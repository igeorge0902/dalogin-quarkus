package com.dalogin.client.service;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/rest/news-settings/screen")
@Produces(MediaType.APPLICATION_JSON)
public interface NewsSettings {
    @GET
    Response getNewsScreen();

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    Response putNewsScreen(String json);
}
