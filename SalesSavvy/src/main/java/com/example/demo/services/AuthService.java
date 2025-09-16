package com.example.demo.services;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.demo.entities.JWTToken;
import com.example.demo.entities.User;
import com.example.demo.repositories.JWTTokenRepository;
import com.example.demo.repositories.UserRepository;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Service
public class AuthService {

	private final Key SIGNING_KEY;
	
	private UserRepository userRepository;
	private JWTTokenRepository jwtTokenRepository;
	private BCryptPasswordEncoder passwordEncoder;
	
	@Autowired
	public AuthService(UserRepository userRepository, JWTTokenRepository jwtTokenRepository,
			@Value("${jwt.secret}") String jwtSecret) {
		super();
		this.userRepository = userRepository;
		this.jwtTokenRepository = jwtTokenRepository;
		this.passwordEncoder = new BCryptPasswordEncoder();
		
		if(jwtSecret.getBytes(StandardCharsets.UTF_8).length<64 ) {
			throw new IllegalArgumentException("JWT_SECRET in application.properties must be at least 64 bytes long for HS512");
		}
		
		this.SIGNING_KEY=Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
	}
	
	public User authenticate(String username,String password) {
		User user=userRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("Invalid username"));
		
		if(!passwordEncoder.matches(password, user.getPassword())) {  	//matches() method will decode and checks
			throw new RuntimeException("Invalid Password");
		}
		return user;
	}
	
	public String generateToken(User user) {
		String token;
		LocalDateTime now=LocalDateTime.now();
		JWTToken existingToken=jwtTokenRepository.findByUserId(user.getUserId());
		if(existingToken!=null && now.isBefore(existingToken.getExpiresAt())) {
			token=existingToken.getToken();
		}
		else {
			token=generateNewToken(user);
			if(existingToken!=null) {
				jwtTokenRepository.delete(existingToken);
			}
			saveToken(user,token);
		}
		return token;
	}

	private void saveToken(User user, String token) {
		// TODO Auto-generated method stub
		JWTToken jwtToken=new JWTToken(user,token,LocalDateTime.now().plusHours(1));
		
	}

	private String generateNewToken(User user) {
		// TODO Auto-generated method stub
		
		return Jwts.builder()
				.setSubject(user.getUsername())
				.claim("role", user.getRole().name())
				.setExpiration(new Date(System.currentTimeMillis()+3600000))
				.signWith(SIGNING_KEY,SignatureAlgorithm.HS512)
				.compact();
	}

	public boolean validateToken(String token) {
		try {
			System.out.println("VALIDATING TOKEN...");
			
			Jwts.parserBuilder()
			.setSigningKey(SIGNING_KEY)
			.build()
			.parseClaimsJws(token);
			
			Optional<JWTToken> jwtToken=jwtTokenRepository.findByToken(token);
			if(jwtToken.isPresent()) {
				System.err.println("Token Expiry: " + jwtToken.get().getExpiresAt());
				System.err.println("Current Time: " + LocalDateTime.now());
				return jwtToken.get().getExpiresAt().isAfter(LocalDateTime.now());
			}
			return false;
		}
		catch(Exception e) {
			System.err.println("Token validation failed: " + e.getMessage());
			return false;
		}
	}

	public String extractUsername(String token) {
		// TODO Auto-generated method stub
		return Jwts.parserBuilder()
		.setSigningKey(SIGNING_KEY)
		.build()
		.parseClaimsJws(token)
		.getBody()
		.getSubject();
	}
	
	public JWTToken extractToken(String token) {
		return null;
	}
	

	
	
}
