package com.jason.shopping.security.util;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Calendar;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.core.userdetails.UserDetails;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;


public class JWTUtil {

	private final static byte[] keyBytes = new byte[256];

	static {
		try {
			SecureRandom.getInstanceStrong().nextBytes(keyBytes);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public String generateToken(UserDetails userDetails) {

		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.MINUTE, 10);

		Claims claims = Jwts.claims();
		claims.put("account", userDetails.getUsername());
		claims.setExpiration(calendar.getTime());
		Key secretKey = Keys.hmacShaKeyFor(keyBytes);

		return Jwts.builder().setClaims(claims).signWith(secretKey).compact();
	}

	public Map<String, Object> parseToken(String token) {
		Key secretKey = Keys.hmacShaKeyFor(keyBytes);

		JwtParser parser = Jwts.parserBuilder().setSigningKey(secretKey).build();

		Claims claims = parser.parseClaimsJws(token).getBody();

		return claims.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
	}
}
