package com.zygen.etax.endpoint;

import org.apache.commons.text.StringEscapeUtils;
import org.apache.tomcat.util.security.Escape;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;

import com.zygen.etax.model.SignPdfRequest;
import com.zygen.etax.model.SignPdfResponse;
import com.zygen.etax.model.SignXmlRequest;
import com.zygen.etax.model.SignXmlResponse;
import com.zygen.etax.repo.EtaxRepository;
import com.zygen.etax.xades.XadesProperties;


@Endpoint
@EnableConfigurationProperties({XadesProperties.class})
public class EtaxEndpoint {
	
	private static final Logger log = LoggerFactory.getLogger(EtaxEndpoint.class);
	private static final String NAMESPACE_URI = "http://model.etax.zygen.com/";
	private XadesProperties properties;
	
	public EtaxEndpoint(XadesProperties properties) {
		this.properties = properties;
	}
	
	@PayloadRoot(namespace = NAMESPACE_URI, localPart = "SignXmlRequest")
	@ResponsePayload
	public SignXmlResponse SignXmlRequest(@RequestPayload SignXmlRequest request) {
		log.info("Request Key : " + request.getKey().getValue());
		EtaxRepository etaxRepo = new EtaxRepository(request.getKey().getValue(),properties);
		etaxRepo.callAgentGetXml(request.getXmlContent().getValue());
		return etaxRepo.getSignXmlResponse();
	}
	
	@PayloadRoot(namespace = NAMESPACE_URI, localPart = "SignPdfRequest")
	@ResponsePayload
	public SignPdfResponse SignPdfRequest(@RequestPayload SignPdfRequest request) {
		log.info("Request Key : " + request.getKey().getValue());
		EtaxRepository etaxRepo = new EtaxRepository(request.getKey().getValue(),properties);
		etaxRepo.callAgentGetPdf(request.getPdfBase64().getValue(),request.getSignedXmlContent().getValue());
		return etaxRepo.getSignPdfResponse();
		
	}
	
}
