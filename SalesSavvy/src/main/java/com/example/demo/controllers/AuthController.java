package com.example.demo.controllers;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.example.demo.dto.LoginRequest;
import com.example.demo.entities.User;
import com.example.demo.services.AuthService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

@Controller
@RequestMapping("/api/auth")
//@CrossOrigin(origins="http://localhost:5174",allowCredentials="true")
public class AuthController {
	AuthService authService;

	@Autowired
	public AuthController(AuthService authService) {
		super();
		this.authService = authService;
	}
	
	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest,HttpServletResponse response){
		try {
			User user=authService.authenticate(loginRequest.getUsername(), loginRequest.getPassword());
			String token=authService.generateToken(user);
			Cookie cookie=new Cookie("authToken",token);
			cookie.setHttpOnly(true);
			cookie.setSecure(false);
			cookie.setPath("/");
			cookie.setMaxAge(3600);
			cookie.setDomain("localhost");
			//add cookie to response
//			response.addCookie(cookie);
			response.addHeader("Set-Cookie", String.format("authToken=%s; HttpOnly; Path=/; Max-Age=3600; SameSite=None", token));
			
			Map<String,Object> responseBody = new HashMap<>();
			responseBody.put("message", "Login Successful");
			responseBody.put("role", user.getRole().name());  	//name() method is used to fetch value from an enum
			responseBody.put("username", user.getUsername());
			
			return ResponseEntity.ok(responseBody);
		}catch(Exception e) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error",e.getMessage()));
		}
	}
	
	
}
