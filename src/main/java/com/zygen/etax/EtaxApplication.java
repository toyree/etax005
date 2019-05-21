package com.zygen.etax;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;

import com.zygen.etax.util.EtaxProperties;
import com.zygen.etax.util.EtaxToken;

@SpringBootApplication
@EnableConfigurationProperties({ EtaxProperties.class })	
public class EtaxApplication {
	
	@Autowired
	private EtaxToken etaxToken;

	public static void main(String[] args) {
		ApplicationContext context = SpringApplication.run(EtaxApplication.class, args);
	}
	
}
