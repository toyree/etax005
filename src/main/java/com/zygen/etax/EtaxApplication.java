package com.zygen.etax;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import com.zygen.etax.util.EtaxProperties;

@SpringBootApplication
@EnableConfigurationProperties({ EtaxProperties.class })	
public class EtaxApplication {
	
	public static void main(String[] args) {
		SpringApplication.run(EtaxApplication.class, args);
	}
	
}
