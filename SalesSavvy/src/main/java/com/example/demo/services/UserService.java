package com.example.demo.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.demo.entities.User;
import com.example.demo.repositories.UserRepository;

@Service
public class UserService {
	
	private UserRepository userRepository;
	private BCryptPasswordEncoder passwordEncoder;
	
	private UserService(UserRepository userRepository) {
		this.userRepository=userRepository;
		this.passwordEncoder=new BCryptPasswordEncoder();
	}

	public User registerUser(User user) {
//		User existingUser=repository.findByUsername(user.getUsername());
//		if(existingUser!=null) {
//			throw new RuntimeException("Username already exist");
//		}
//		existingUser=repository.findByEmail(user.getEmail());
//		if(existingUser!=null) {
//			throw new RuntimeException("Email already exist");
//		}
		
		if(userRepository.findByUsername(user.getUsername()).isPresent()) {
			throw new RuntimeException("User Already exist");
		}
		if(userRepository.findByEmail(user.getEmail()).isPresent()) {
			throw new RuntimeException("User with this email Already exist");
		}
		// Before saving user
		user.setPassword(passwordEncoder.encode(user.getPassword())); 

		return userRepository.save(user);
	}
	
}
