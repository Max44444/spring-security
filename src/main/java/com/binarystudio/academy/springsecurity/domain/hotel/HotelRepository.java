package com.binarystudio.academy.springsecurity.domain.hotel;

import com.binarystudio.academy.springsecurity.domain.hotel.model.Hotel;
import org.springframework.stereotype.Repository;

import java.util.*;

@Repository
public class HotelRepository {
	private final List<Hotel> hotels = new LinkedList<>();

	public HotelRepository() {
		hotels.add(Hotel.of("InterContinental - Los Angeles Downtown", "Boasting an outdoor pool, InterContinental - Los Angeles Downtown is situated in the Downtown Los Angeles district of Los Angeles. The property has an on-site restaurant and free WiFi throughout. An American breakfast is available every morning at the property.", "https://images.unsplash.com/photo-1566073771259-6a8506099945?ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&ixlib=rb-1.2.1&auto=format&fit=crop&w=1950&q=80"));
		hotels.add(Hotel.of("Hotel Becket Lake Tahoe", "Hotel Becket is at the base of Heavenly Village and is central to South Lake Tahoe restaurants, bars, shopping, casinos and 5 minutes' walk to Lake Tahoe beach. WiFi is available and free private parking is available on site at this pet-friendly, nonsmoking hotel.", "https://images.unsplash.com/photo-1444201983204-c43cbd584d93?ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&ixlib=rb-1.2.1&auto=format&fit=crop&w=1950&q=80"));
		hotels.add(Hotel.of("InterContinental San Francisco", "Overlooking San Francisco's SoMa area and moments from top city center sites, InterContinental San Francisco provides guests with modern in-room amenities. Shopping and dining opportunities in Union Square are 10 minutes’ walk away.", "https://images.unsplash.com/photo-1455587734955-081b22074882?ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&ixlib=rb-1.2.1&auto=format&fit=crop&w=1920&q=80"));
		hotels.add(Hotel.of("Beach Retreat & Lodge at Tahoe", "Located beachfront on Lake Tahoe, Beach Retreat & Lodge at Tahoe features a marina, 2 restaurants and free WiFi. A fireplace is offered in each warmly-decorated guest room. Parking is available.", "https://images.unsplash.com/photo-1445019980597-93fa8acb246c?ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&ixlib=rb-1.2.1&auto=format&fit=crop&w=1353&q=80"));
		hotels.add(Hotel.of("Sheraton Gateway Los Angeles", "This modern hotel provides free 24-hour dedicated shuttle service to Los Angeles International Airport, just a 3-minute drive away. Guests can relax in the outdoor heated pool. Dining options are available on site. Each guest room includes a 50-inch LCD TV.", "https://images.unsplash.com/photo-1571003123894-1f0594d2b5d9?ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&ixlib=rb-1.2.1&auto=format&fit=crop&w=687&q=80"));
		hotels.add(Hotel.of("Carmel Mission Inn", "Surrounded by attractions such as Cannery Row, the Monterey Bay Aquarium and Fisherman's Wharf, this hotel offers relaxing activities and sophisticated dining options in the center of Carmel, California.", "https://images.unsplash.com/photo-1498503182468-3b51cbb6cb24?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1350&q=80"));
		hotels.add(Hotel.of("Bear Creek Resort", "Featuring a seasonal outdoor pool and hot tub and offering mountain views, Bear Creek Resort is located in Big Bear Lake, 901 m from Big Bear Marina. Free WiFi is available throughout the property and free private parking is available on site.", "https://images.unsplash.com/photo-1529290130-4ca3753253ae?ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&ixlib=rb-1.2.1&auto=format&fit=crop&w=1355&q=80"));
		hotels.add(Hotel.of("Monterey Tides", "Offering direct beach access and a year-round outdoor heated pool, Monterey Tides, is 3 mi from Monterey Bay Aquarium. Old Fisherman's Wharf is 10 minutes' drive away. All comfortably furnished guest rooms include free WiFi.", "https://images.unsplash.com/photo-1520250497591-112f2f40a3f4?ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&ixlib=rb-1.2.1&auto=format&fit=crop&w=1350&q=80"));
		hotels.add(Hotel.of("The Getaway", "The Naval Postgraduate School, Monterey is a short drive from The Getaway. Monterey Peninsula College is also within driving distance of the hotel. The Monterey Peninsula Airport is 15 minutes' drive from the hotel.", "https://images.unsplash.com/photo-1561409037-c7be81613c1f?ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&ixlib=rb-1.2.1&auto=format&fit=crop&w=967&q=80"));
	}

	public Optional<Hotel> getById(UUID id) {
		return hotels.stream()
				.filter(h -> h.getId().equals(id))
				.findAny();
	}

	public List<Hotel> getHotels() {
		return Collections.unmodifiableList(hotels);
	}

	public Hotel save(Hotel hotel) {
		var foundHotel = getById(hotel.getId());
		if (foundHotel.isPresent()) {
			var savedHotel = foundHotel.get();
			savedHotel.setDescription(hotel.getDescription());
			savedHotel.setName(hotel.getName());
			savedHotel.setImageUrl(hotel.getImageUrl());
			savedHotel.setOwnerId(hotel.getOwnerId());
			return savedHotel;
		} else {
			var clonedHotel = hotel.cloneWithNewId();
			hotels.add(clonedHotel);
			return clonedHotel;
		}
	}

	public boolean delete(UUID hotelId) {
		return hotels.removeIf(hotel -> hotel.getId().equals(hotelId));
	}
}
