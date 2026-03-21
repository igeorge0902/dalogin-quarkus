package com.dalogin.client.service;

import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/rest")
public interface Purchases {
    @GET
    @Path("/book/purchases")
    @Produces(MediaType.APPLICATION_JSON)
    Response getAllPurchases();

    @GET
    @Path("/book/purchases/tickets")
    @Produces(MediaType.APPLICATION_JSON)
    Response getTickets(@QueryParam(value = "purchaseId") String purchaseId);

    @POST
    @Path("/book/managepurchases")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    Response managePurchases(
            @FormParam("purchaseId") String purchaseId,
            @FormParam("ticketsToBeCancelled") String ticketsToBeCancelled
    );

    @POST
    @Path("/book/deletepurchases")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    Response deletePurchases(
            @FormParam("purchaseId") String purchaseId
            );

    @POST
    @Path("book/payment/fullcheckout2")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    Response checkOut(
            @FormParam("orderId") String orderId,
            @FormParam("seatsToBeReserved") String seatsToBeReserved,
            @FormParam("payment_method_nonce") String payment_method_nonce
    );

    @GET
    @Path("book/payment/clientToken")
    @Produces(MediaType.APPLICATION_JSON)
    Response clientToken();
}
