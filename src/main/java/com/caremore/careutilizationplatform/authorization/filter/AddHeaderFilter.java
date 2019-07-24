package com.caremore.careutilizationplatform.authorization.filter;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;

import com.caremore.careutilizationplatform.authorization.config.yaml.AuthConfig;
import com.caremore.careutilizationplatform.authorization.jwt.JWTParser;
import com.caremore.careutilizationplatform.config.SharedConfig;
import com.caremore.careutilizationplatform.utils.Constants;
import com.caremore.careutilizationplatform.utils.Utils;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;

public class AddHeaderFilter extends ZuulFilter {

	@Autowired
	JWTParser jwtParser;

	@Autowired
	SharedConfig config;

	@Autowired
	private AuthConfig authConfig;

	private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());

	@Override
	public Object run() throws ZuulException {
		RequestContext ctx = RequestContext.getCurrentContext();
		HttpServletRequest request = ctx.getRequest();

		// Add CUE Application id in the header.
		if (Utils.containsInArrayRegEx(authConfig.getHeader().getCue(),
				Utils.requestURIWithoutContext(request.getContextPath(), request.getRequestURI())))
			ctx.addZuulRequestHeader(Constants.CUE_APPLICATION_KEY, config.getCueApplicationKey());

		// Add USERNAME header
		if (Utils.containsInArrayRegEx(authConfig.getHeader().getUsername(),
				Utils.requestURIWithoutContext(request.getContextPath(), request.getRequestURI()))) {
			ctx.addZuulRequestHeader(Constants.USERNAME,
					jwtParser.getUser(request.getHeader(Constants.AUTHORIZATION)).getUserName());
			ctx.addZuulRequestHeader(Constants.USERID,
					jwtParser.getUser(request.getHeader(Constants.AUTHORIZATION)).getId());
		}

		// Add WSO2 Token header
		if (Utils.containsInArrayRegEx(authConfig.getHeader().getWso2token(),
				Utils.requestURIWithoutContext(request.getContextPath(), request.getRequestURI())))
			ctx.addZuulRequestHeader(Constants.AUTHORIZATION,
					Constants.BEARER + jwtParser.getWSO2Token(request.getHeader(Constants.AUTHORIZATION)));

		LOGGER.debug("ZUUL:- " + request.getMethod() + " request to " + request.getRequestURL().toString());
		return null;
	}

	@Override
	public boolean shouldFilter() {
		return true;
	}

	@Override
	public int filterOrder() {
		return 1;
	}

	@Override
	public String filterType() {
		return FilterConstants.PRE_TYPE;
	}

}
