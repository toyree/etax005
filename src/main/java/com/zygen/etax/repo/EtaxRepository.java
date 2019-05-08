package com.zygen.etax.repo;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

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
	private XadesProperties xadesProperties;

//	@PostConstruct
//	public void initData() {
//		log.info("EtaxRepo initData Process");
//		factory = new ObjectFactory();
//		signXmlResponse = factory.createSignXmlResponse();
//	}
	
	public EtaxRepository() {
		factory = new ObjectFactory();
	}
	
	public XadesProperties getXadesProperties() {
		return xadesProperties;
	}

	public void setXadesProperties(XadesProperties xadesProperties) {
		this.xadesProperties = xadesProperties;
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
		log.info("CallAgentGetXml");
		signXmlResponse = factory.createSignXmlResponse();
		SignXmlModel signXmlModel = factory.createSignXmlModel();
		signXmlModel.setRespCode(1234);
		signXmlModel.setRespName(factory.createBaseModelRespName("Reponse1234"));
		XadesBesSign xadesBesSign = new XadesBesSign(signingConfigName , xadesProperties);
		InputStream inputXmlContent = new ByteArrayInputStream(xmlContent.getBytes(StandardCharsets.UTF_8));
		try {
			signXmlModel.setSignedXml(factory.createSignXmlModelSignedXml(xadesBesSign.signXML(inputXmlContent).toString()));
		} catch (Exception e) {
			log.error(e.getMessage());
		}
		signXmlResponse.setSignXmlResult(factory.createSignXmlModel(signXmlModel));
	}
	
	public void callAgentGetPdf(String signingConfigName, String pdfContent) {
		log.info("CallAgentGetPdf");
		signPdfResponse = factory.createSignPdfResponse();
		SignPdfModel signPdfModel = factory.createSignPdfModel();
		signPdfModel.setRespCode(1234);
		signPdfModel.setRespName(factory.createBaseModelRespName("Response1234"));
		XadesBesSign xadesBesSign = new XadesBesSign(signingConfigName , xadesProperties);
		InputStream inputPdfContent = new ByteArrayInputStream(pdfContent.getBytes(StandardCharsets.UTF_8));
		try {
			signPdfModel.setSignedPdf(factory.createSignPdfModelSignedPdf(xadesBesSign.signPdf(inputPdfContent).toString()));
		} catch (Exception e) {
			log.error(e.getMessage());
		}
		signPdfResponse.setSignPdfResult(factory.createSignPdfModel(signPdfModel));
	}
	

}
