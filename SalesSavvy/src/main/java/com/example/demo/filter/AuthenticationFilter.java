package com.example.demo.filter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import com.example.demo.entities.Role;
import com.example.demo.entities.User;
import com.example.demo.repositories.UserRepository;
import com.example.demo.services.AuthService;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


@WebFilter(urlPatterns="/api/*")
public class AuthenticationFilter implements Filter{

	private static final Logger logger=LoggerFactory.getLogger(AuthenticationFilter.class);
	private final AuthService authService;
	private final UserRepository userRepository;
	
	private static final String ALLOWED_ORIGIN="http://localhost:5174";
	
	private static final String[] UNAUTHENTICATED_PATHS= {
		"/api/users/register",
		"api/auth/login"
	};
	
	
	@Autowired
	public AuthenticationFilter(AuthService authService, UserRepository userRepository) {
		System.out.println("Filter started");
		this.authService = authService;
		this.userRepository = userRepository;
	}





	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// TODO Auto-generated method stub
		
	}
	
	private void executeFilterLgic(ServletRequest request,ServletResponse response, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest httpRequest=(HttpServletRequest) request;	//to get requestURI we need httpServletRequest and HttpServletResponse
		HttpServletResponse httpResponse=(HttpServletResponse) response;
		
		String requestURI=httpRequest.getRequestURI();
		logger.info("request URI :{}",requestURI);
		
		if(Arrays.asList(UNAUTHENTICATED_PATHS).contains(requestURI)) {
			chain.doFilter(request, response);
			return;
		}
		
		if(httpRequest.getMethod().equalsIgnoreCase("OPTIONS")) {
			setCORSHeaders(httpResponse);
			return;
		}
		
		String token=getAuthTokenFromCookies(httpRequest);
		System.out.println(token);
		if(token==null || !authService.validateToken(token)) {
			sendErrorResponse(httpResponse,HttpServletResponse.SC_UNAUTHORIZED,"Unauthorized: invalid or missing token");
			return;
		}
		
		String username=authService.extractUsername(token);
		Optional<User> userOptional=userRepository.findByUsername(username);
		if(userOptional.isEmpty()) {
			sendErrorResponse(httpResponse,HttpServletResponse.SC_UNAUTHORIZED,"Unauthorized: user not found");
			return;
		}
		
		User authenticatedUser=userOptional.get();
		Role role=authenticatedUser.getRole();
		
		logger.info("Authenticated User: {}, Role: {} ", authenticatedUser.getUsername(),role);
		
		if(requestURI.startsWith("/admin/") && role != Role.ADMIN) {
			sendErrorResponse(httpResponse,HttpServletResponse.SC_FORBIDDEN,"Forbidden: Admin access required");
			return;
		}
		
		if(requestURI.startsWith("/api/") && role != Role.CUSTOMER || role != Role.ADMIN) {
			sendErrorResponse(httpResponse,HttpServletResponse.SC_FORBIDDEN,"Forbidden: Customer access required");
			return;
		}
		
		httpRequest.setAttribute("authenticatedUser",authenticatedUser);
		chain.doFilter(httpRequest, httpResponse);
		
	}





	private void sendErrorResponse(HttpServletResponse response, int statusCode, String message) throws IOException {
		// TODO Auto-generated method stub
		response.setStatus(statusCode);
		response.getWriter()
.write(message);		
	}





	private String getAuthTokenFromCookies(HttpServletRequest request) {
		// TODO Auto-generated method stub
		Cookie[] cookies=request.getCookies();
		if(cookies!=null) {
			return Arrays.stream(cookies) 
					.filter(cookie -> "authTOken".equals(cookie.getName()))
					.map(Cookie::getValue)
					.findFirst()
					.orElse(null);
		}
		return null;
	}





	private void setCORSHeaders(HttpServletResponse response) {
		// TODO Auto-generated method stub
		response.setHeader("Access-Control-Allow-Origin",ALLOWED_ORIGIN);
		response.setHeader("Access-Control-Allow-Methods","GET , POST , PUT , DELETE , OPTIONS");
		response.setHeader("Access-Control-Allow-Headers","Content-Type,Authorization");
		response.setHeader("Access-Control-Allow-Credentials","true");
		response.setStatus(HttpServletResponse.SC_OK);
		
	}

}
