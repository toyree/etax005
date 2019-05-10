package com.zygen.etax.repo;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.zygen.etax.model.ObjectFactory;
import com.zygen.etax.model.SignPdfModel;
import com.zygen.etax.model.SignPdfResponse;
import com.zygen.etax.model.SignXmlModel;
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

	public void callAgentGetXml(String signingConfigName, String xmlContent) {
		log.info("Request Key : " + key + " CallAgentGetXml");
		signXmlResponse = factory.createSignXmlResponse();
		SignXmlModel signXmlModel = factory.createSignXmlModel();
		XadesBesSign xadesBesSign = new XadesBesSign(properties);
		xadesBesSign.setKey(key);
		xadesBesSign.setSigingConfig(signingConfigName);
		InputStream inputXmlContent = new ByteArrayInputStream(xmlContent.getBytes(StandardCharsets.UTF_8));
		try {
			signXmlModel.setSignedXml(
					factory.createSignXmlModelSignedXml(xadesBesSign.signXML(inputXmlContent).toString()));
		} catch (Exception e) {
			log.error("Request Key : " + key + " " + e.getMessage());
		}
		signXmlResponse.setKey(factory.createSignXmlResponseKey(key));
		signXmlResponse.setSignXmlResult(factory.createSignXmlModel(signXmlModel));
	}

	public void callAgentGetPdf(String signingConfigName, String pdfContent, String xmlContent) {
		log.info("Request Key : " + key + " CallAgentGetPdf");
		signPdfResponse = factory.createSignPdfResponse();
		SignPdfModel signPdfModel = factory.createSignPdfModel();
		XadesBesSign xadesBesSign = new XadesBesSign(properties);
		xadesBesSign.setKey(key);
		xadesBesSign.setSigingConfig(signingConfigName);
		byte[] pdfByte = Base64.getDecoder().decode(pdfContent.getBytes(StandardCharsets.UTF_8));
		InputStream inputPdfContent = new ByteArrayInputStream(pdfByte);
		InputStream inputXmlContent = new ByteArrayInputStream(xmlContent.getBytes(StandardCharsets.UTF_8));
		try {
			signPdfModel.setSignedPdf(factory.createSignPdfModelSignedPdf(xadesBesSign.signPdf(inputPdfContent, inputXmlContent).toString()));
		} catch (Exception e) {
			log.error("Request Key : " + key + " " + e.getMessage());
		}
		signPdfResponse.setKey(factory.createSignPdfResponseKey(this.key));
		signPdfResponse.setSignPdfResult(factory.createSignPdfModel(signPdfModel));
		
	}

}
