package com.caremore.careutilizationplatform.authorization.config.yaml;

import java.util.ArrayList;
import java.util.List;

public class AuthConfigHeader {

	private List<String> username = new ArrayList<>();
	private List<String> wso2token = new ArrayList<>();
	private List<String> cue = new ArrayList<>();

	public List<String> getWso2token() {
		return wso2token;
	}

	public void setWso2token(List<String> wso2token) {
		this.wso2token = wso2token;
	}

	public List<String> getUsername() {
		return username;
	}

	public void setUsername(List<String> username) {
		this.username = username;
	}

	public List<String> getCue() {
		return cue;
	}

	public void setCue(List<String> cue) {
		this.cue = cue;
	}

}
