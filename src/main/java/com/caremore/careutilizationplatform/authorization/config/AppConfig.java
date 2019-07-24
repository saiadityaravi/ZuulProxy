package com.caremore.careutilizationplatform.authorization.config;

import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.multipart.MultipartResolver;
import org.springframework.web.multipart.support.StandardServletMultipartResolver;

import com.caremore.careutilizationplatform.authorization.filter.AddHeaderFilter;
import com.caremore.careutilizationplatform.config.SharedConfig;
import com.netflix.zuul.ZuulFilter;

@Configuration
@ComponentScan(basePackages = { "com.caremore" })
public class AppConfig {

	@Autowired
	SharedConfig config;

	@Bean
	public DataSource dataSource() {
		DriverManagerDataSource dataSource = new DriverManagerDataSource();
		dataSource.setDriverClassName(config.getJdbcDriverClassName());
		dataSource.setUrl(config.getJdbcUrl());
		return dataSource;
	}

	@Bean
	public JdbcTemplate jdbcTemplate(DataSource dataSource) {
		JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
		jdbcTemplate.setResultsMapCaseInsensitive(true);
		jdbcTemplate.setFetchSize(40000);
		return jdbcTemplate;
	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public ZuulFilter cupFilter() {
		return new AddHeaderFilter();
	}

	// Add support to enable multipart in PUT.
	@Bean
	public MultipartResolver multipartResolver() {
		return new StandardServletMultipartResolver() {
			@Override
			public boolean isMultipart(HttpServletRequest request) {
				if (!Arrays.asList("put", "post").contains(request.getMethod().toLowerCase()))
					return false;

				return (request.getContentType() != null
						&& request.getContentType().toLowerCase().startsWith("multipart/"));
			}
		};
	}

}