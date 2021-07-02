package com.binarystudio.academy.springsecurity.domain.hotel.model;

import lombok.Data;

import java.util.UUID;

@Data
public class Hotel {
    private UUID id;
    private String name;
    private String description;
    private String imageUrl;
    private UUID ownerId;

    public static Hotel of(String name, String description, String imageUrl) {
        return of(name, description, imageUrl, null);
    }

    public static Hotel of(String name, String description, String imageUrl, UUID ownerId) {
        var hotel = new Hotel();
        hotel.setId(UUID.randomUUID());
        hotel.setName(name);
        hotel.setDescription(description);
        hotel.setImageUrl(imageUrl);
        hotel.setOwnerId(ownerId);
        return hotel;
    }

    public Hotel cloneWithNewId() {
        return of(name, description, imageUrl);
    }
}
