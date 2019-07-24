package com.caremore.careutilizationplatform.authorization.config.yaml;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "authconfig")
public class AuthConfig {

	private HashMap<String, List<String>> allow = new HashMap<>();
	private List<String> unprotected = new ArrayList<>();
	private AuthConfigHeader header = new AuthConfigHeader();

	public Map<String, List<String>> getAllow() {
		return allow;
	}

	public void setAllow(Map<String, List<String>> allow) {
		this.allow = (HashMap<String, List<String>>) allow;
	}

	public List<String> getAllow(String role) {
		return (this.allow.get(role) == null) ? new ArrayList<>() : this.allow.get(role);
	}

	public AuthConfigHeader getHeader() {
		return header;
	}

	public void setHeader(AuthConfigHeader header) {
		this.header = header;
	}

	public List<String> getUnprotected() {
		return unprotected;
	}

	public void setUnprotected(List<String> unprotected) {
		this.unprotected = unprotected;
	}

}
