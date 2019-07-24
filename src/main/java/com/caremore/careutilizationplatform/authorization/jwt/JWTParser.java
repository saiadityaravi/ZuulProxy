package com.caremore.careutilizationplatform.authorization.jwt;

import java.security.KeyPair;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.stereotype.Component;

import com.caremore.careutilizationplatform.config.SharedConfig;
import com.caremore.careutilizationplatform.model.CUser;
import com.caremore.careutilizationplatform.utils.Constants;
import com.google.gson.Gson;
import com.google.gson.JsonElement;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

@Component
public class JWTParser {

	@Autowired
	private SharedConfig config;

	private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());

	private KeyStoreKeyFactory keyStoreKeyFactory;

	private KeyPair keyPair;

	@PostConstruct
	public void init() {
		keyStoreKeyFactory = new KeyStoreKeyFactory(config.getKeystore(), config.getKeystorePassword().toCharArray());
		keyPair = keyStoreKeyFactory.getKeyPair(config.getKeyAlias(), config.getKeyPassword().toCharArray());
	}

	public CUser getUser(String token) throws JwtException {
		Gson gson = new Gson();
		JsonElement jsonElement = gson.toJsonTree(getClaims(token).get(Constants.USERINFO));
		return gson.fromJson(jsonElement, CUser.class);
	}

	public String getWSO2Token(String token) throws JwtException {
		return getUser(token).getWso2token().getAccess_token();
	}

	public String getAppSource(String token) {
		try {
			return getUser(token).getSource();
		} catch (JwtException e) {
			// Nothing to log, there is no App Source in JWT, during login.
		}
		return "";
	}

	private Claims getClaims(String token) {
		try {
			return Jwts.parser().setSigningKey(keyPair.getPublic()).parseClaimsJws(token.replace(Constants.BEARER, ""))
					.getBody();
		} catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException
				| IllegalArgumentException | NullPointerException e) {
			LOGGER.error("JWT parse exception, " + e.getMessage());
			LOGGER.debug("Exception:" + e);
			throw new JwtException(e.getMessage());
		}
	}
}
