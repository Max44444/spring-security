package com.binarystudio.academy.springsecurity.domain.hotel;

import com.binarystudio.academy.springsecurity.domain.hotel.model.Hotel;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

@Service
public class HotelService {
	private final HotelRepository hotelRepository;

	public HotelService(HotelRepository hotelRepository) {
		this.hotelRepository = hotelRepository;
	}

	public void delete(UUID hotelId) {
		// 4. todo: only the owner of the hotel or admin may delete the hotel
		boolean wasDeleted = hotelRepository.delete(hotelId);
		if (!wasDeleted) {
			throw new NoSuchElementException();
		}
	}

	public List<Hotel> getAll() {
		return hotelRepository.getHotels();
	}


	public Hotel update(Hotel hotel) {
		// 4. todo: only the owner of the hotel or admin may update the hotel
		getById(hotel.getId());
		return hotelRepository.save(hotel);
	}

	public Hotel create(Hotel hotel) {
		return hotelRepository.save(hotel);
	}

	public Hotel getById(UUID hotelId) {
		return hotelRepository.getById(hotelId).orElseThrow();
	}
}
