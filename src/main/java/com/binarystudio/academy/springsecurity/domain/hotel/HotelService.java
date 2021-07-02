package com.binarystudio.academy.springsecurity.domain.hotel;

import com.binarystudio.academy.springsecurity.domain.hotel.model.Hotel;
import com.binarystudio.academy.springsecurity.domain.user.model.User;
import com.binarystudio.academy.springsecurity.domain.user.model.UserRole;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

@Service
public class HotelService {

    private final HotelRepository hotelRepository;

    public HotelService(HotelRepository hotelRepository) {
        this.hotelRepository = hotelRepository;
    }

    public void delete(UUID hotelId, User user) {
        var hotel = getById(hotelId);
        if (isHotelOwnerOrAdmin(user, hotel)) {
            boolean wasDeleted = hotelRepository.delete(hotelId);
            if (!wasDeleted) {
                throw new NoSuchElementException();
            }
        } else {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "forbidden to delete hotel");
        }
    }

    public List<Hotel> getAll() {
        return hotelRepository.getHotels();
    }


    public Hotel update(Hotel hotel, User user) {
        var currentHotel = getById(hotel.getId());
        if (isHotelOwnerOrAdmin(user, currentHotel)) {
            getById(hotel.getId());
            return hotelRepository.save(hotel);
        }
        throw new ResponseStatusException(HttpStatus.FORBIDDEN, "forbidden to update hotel");
    }

    public Hotel create(Hotel hotel) {
        return hotelRepository.save(hotel);
    }

    public Hotel getById(UUID hotelId) {
        return hotelRepository.getById(hotelId).orElseThrow();
    }

    public boolean isHotelOwnerOrAdmin(User user, Hotel hotel) {
        if (user == null) {
            return false;
        }
        var isAdmin = user.getAuthorities().contains(UserRole.ADMIN);
        var isOwner = user.getId().equals(hotel.getOwnerId());
        return isAdmin || isOwner;
    }

}
