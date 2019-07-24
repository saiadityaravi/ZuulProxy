package com.caremore.careutilizationplatform.authorization.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.caremore.careutilizationplatform.authorization.config.yaml.AuthConfig;
import com.caremore.careutilizationplatform.model.CUser;
import com.caremore.careutilizationplatform.utils.Constants;
import com.caremore.careutilizationplatform.utils.Utils;

@Component
public class UserAccessFilter {

	@Autowired
	private AuthConfig authConfig;

	private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());

	public String getAccessAuthority(CUser user, String uri) {

		String status = Constants.DENY;
		// If url present in YAML config allow list, ALLOW access else DENY by default.
		if (Utils.containsInArrayRegEx(authConfig.getAllow(user.getRole().toLowerCase()), uri)
				|| Utils.containsInArrayRegEx(authConfig.getAllow(Constants.ALL), uri))
			status = Constants.ALLOW;

		LOGGER.info("USER:" + user.getUserName() + ", ROLE:" + user.getRole().toLowerCase() + ", URI:" + uri
				+ ", STATUS:" + status);
		return status;
	}

}
