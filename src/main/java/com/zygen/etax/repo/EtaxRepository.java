package com.zygen.etax.repo;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.apache.commons.text.StringEscapeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.zygen.etax.model.ObjectFactory;
import com.zygen.etax.model.SignPdfResponse;
import com.zygen.etax.model.SignXmlResponse;
import com.zygen.etax.xades.XadesBesSign;
import com.zygen.etax.xades.XadesProperties;


public class EtaxRepository {

	private static final Logger log = LoggerFactory.getLogger(EtaxRepository.class);
	private SignXmlResponse signXmlResponse;
	private SignPdfResponse signPdfResponse;
	private ObjectFactory factory;
	private XadesProperties properties;
	private String key;
	
	
	
	public EtaxRepository(String key,XadesProperties properties){
		factory = new ObjectFactory();
		this.key = key;
		this.properties = properties;
		log.info("Key = " + key + " Properties = " + properties.toString());
	}

	public SignXmlResponse getSignXmlResponse() {
		return signXmlResponse;
	}

	public void setSignXmlResponse(SignXmlResponse signXmlResponse) {
		this.signXmlResponse = signXmlResponse;
	}

	public SignPdfResponse getSignPdfResponse() {
		return signPdfResponse;
	}

	public void setSignPdfResponse(SignPdfResponse signPdfResponse) {
		this.signPdfResponse = signPdfResponse;
	}

	public void callAgentGetXml(String xmlContent) {
		log.info("Request Key : " + key + " CallAgentGetXml");
		signXmlResponse = factory.createSignXmlResponse();
		XadesBesSign xadesBesSign = new XadesBesSign(properties);
		xadesBesSign.setKey(key);
		xmlContent = StringEscapeUtils.unescapeHtml4(xmlContent);
		log.info(xmlContent);
		InputStream inputXmlContent = new ByteArrayInputStream(xmlContent.getBytes(StandardCharsets.UTF_8));
		try {
			signXmlResponse.setSignXmlResult(factory.createSignXmlRequestXmlContent((StringEscapeUtils.escapeXml10(xadesBesSign.signXML(inputXmlContent).toString()))));
		} catch (Exception e) {
			log.error("Request Key : " + key + " " + e.getMessage());
		}
		signXmlResponse.setKey(factory.createSignXmlResponseKey(key));
	}

	public void callAgentGetPdf(String pdfContent) {
		log.info("Request Key : " + key + " CallAgentGetPdf");
		signPdfResponse = factory.createSignPdfResponse();
		XadesBesSign xadesBesSign = new XadesBesSign(properties);
		xadesBesSign.setKey(key);
		byte[] pdfByte = Base64.getDecoder().decode(pdfContent.getBytes(StandardCharsets.UTF_8));
		InputStream inputPdfContent = new ByteArrayInputStream(pdfByte);

		try {
			signPdfResponse.setSignPdfResult(factory.createSignPdfResponseSignPdfResult(xadesBesSign.signPdf(inputPdfContent).toString()));
		} catch (Exception e) {
			log.error("Request Key : " + key + " " + e.getMessage());
		}
		signPdfResponse.setKey(factory.createSignPdfResponseKey(this.key));
		
	}

}
