package com.caremore.careutilizationplatform.authorization.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.caremore.careutilizationplatform.authorization.jwt.JWTParser;
import com.caremore.careutilizationplatform.model.CUser;
import com.caremore.careutilizationplatform.utils.Constants;
import com.caremore.careutilizationplatform.utils.Utils;
import com.fasterxml.jackson.core.type.TypeReference;

import io.jsonwebtoken.JwtException;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	private JWTParser jwtParser;

	private UserAccessFilter userAccessFilter;

	private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());

	public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTParser jwtParser,
			UserAccessFilter userAccessFilter) {
		super(authenticationManager);
		this.jwtParser = jwtParser;
		this.userAccessFilter = userAccessFilter;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		LOGGER.debug("JWT Authorization");
		String header = req.getHeader(Constants.AUTHORIZATION);
		if (header != null && header.startsWith(Constants.BEARER)) {
			UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
			SecurityContextHolder.getContext().setAuthentication(authentication);
		}
		chain.doFilter(req, res);
	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		try {
			CUser user = jwtParser.getUser(request.getHeader(Constants.AUTHORIZATION));
			List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
			grantedAuthorities.add(new SimpleGrantedAuthority(userAccessFilter.getAccessAuthority(user,
					Utils.requestURIWithoutContext(request.getContextPath(), request.getRequestURI()))));
			return new UsernamePasswordAuthenticationToken(user, null, grantedAuthorities);
		} catch (JwtException e) {
			LOGGER.error("Processing JWT exception," + e.getMessage());
			LOGGER.debug("Exception:" + e);
		}
		return null;
	}

	class CUPUserJSONMapper extends TypeReference<CUser> {

	}

}
