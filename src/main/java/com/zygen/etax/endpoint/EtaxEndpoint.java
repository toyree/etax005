package com.zygen.etax.endpoint;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;

import com.zygen.etax.model.SignPdfRequest;
import com.zygen.etax.model.SignPdfResponse;
import com.zygen.etax.model.SignXmlRequest;
import com.zygen.etax.model.SignXmlResponse;
import com.zygen.etax.repo.EtaxRepository;


@Endpoint
public class EtaxEndpoint {
	
	private static final Logger log = LoggerFactory.getLogger(EtaxEndpoint.class);
	private static final String NAMESPACE_URI = "http://model.etax.zygen.com/";

	private EtaxRepository etaxRepo;

	@Autowired
	public EtaxEndpoint(EtaxRepository etaxRepo) {
		log.info("Autowired EtaxEndpoint Process");
		this.etaxRepo = etaxRepo;
	}

	@PayloadRoot(namespace = NAMESPACE_URI, localPart = "SignXmlRequest")
	@ResponsePayload
	public SignXmlResponse SignXmlRequest(@RequestPayload SignXmlRequest request) {
		log.info("SignXmlRequeest SigningConfigName : " + request.getSigningConfigName().getValue());
		log.info(request.getXmlContent().getValue());
		etaxRepo.callAgent(request.getSigningConfigName().getValue(), request.getXmlContent().getValue());
		return etaxRepo.getResponse();
	}
	
	@PayloadRoot(namespace = NAMESPACE_URI, localPart = "SignPdfRequest")
	@ResponsePayload
	public SignPdfResponse SignPdfRequest(@RequestPayload SignPdfRequest request) {
		return null;
		
	}
	
}
