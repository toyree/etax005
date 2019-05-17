package com.zygen.etax.repo;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.annotation.PostConstruct;

import org.apache.commons.text.StringEscapeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.zygen.etax.model.ObjectFactory;
import com.zygen.etax.model.SignPdfResponse;
import com.zygen.etax.model.SignXmlResponse;
import com.zygen.etax.util.EtaxFileService;
import com.zygen.etax.util.EtaxProperties;

@Component
public class EtaxRepository {

	private static final Logger log = LoggerFactory.getLogger(EtaxRepository.class);
	@Autowired
	private EtaxProperties etaxProperties;
	private SignXmlResponse signXmlResponse;
	private SignPdfResponse signPdfResponse;
	private ObjectFactory factory;
	private String key;

	@PostConstruct
	public void init() {
		factory = new ObjectFactory();
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

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public void callAgentGetXml(String xmlContent) {
		log.info("Request Key : " + key + " CallAgentGetXml");
		signXmlResponse = factory.createSignXmlResponse();
		try {
			EtaxSigner etaxSigner = new EtaxSigner();
			etaxSigner.setXadesSigner(etaxProperties.getCs11_lib_path(), etaxProperties.getCs11_provider_name(),
					etaxProperties.getCs11_slot_id(), etaxProperties.getCs11_password());
			xmlContent = StringEscapeUtils.unescapeHtml4(xmlContent);
			InputStream inputXmlContent = new ByteArrayInputStream(xmlContent.getBytes(StandardCharsets.UTF_8));
			signXmlResponse.setSignXmlResult(factory.createSignXmlRequestXmlContent((StringEscapeUtils.escapeXml10(
					etaxSigner.signXML(inputXmlContent, etaxProperties.getTemp_file_path() + key + "_callxml.xml")
							.toString()))));
		} catch (Exception e) {
			log.error(e.getMessage());
		}
		signXmlResponse.setKey(factory.createSignXmlResponseKey(key));
	}

	public void callAgentGetPdf(String pdfContent) {
		log.info("callAgentGetPdf");
		signPdfResponse = factory.createSignPdfResponse();
		try {
			String pdfPath = etaxProperties.getTemp_file_path() + key + "_callpdf.pdf";
			String signedPdfPath = etaxProperties.getTemp_file_path() + key + "signed_callpdf.pdf";
			byte[] pdfByte = Base64.getDecoder().decode(pdfContent.getBytes(StandardCharsets.UTF_8));
			InputStream isPdfContent = new ByteArrayInputStream(pdfByte);
			EtaxFileService.createTempFile(pdfPath, isPdfContent);
			EtaxSigner  etaxSigner = new EtaxSigner();
			etaxSigner.pdfGetKeyStore(etaxProperties.getCs11_provider_name(), etaxProperties.getCs11_slot_id(),
					etaxProperties.getCs11_lib_path(), etaxProperties.getType(), etaxProperties.getCs11_password());
			signPdfResponse.setSignPdfResult(factory.createSignPdfResponseSignPdfResult(
					etaxSigner.signPDF(pdfPath, signedPdfPath).toString()));
			EtaxFileService.deleteTempFile(pdfPath);
		} catch (Exception e) {
			log.error(e.getMessage());
		}
		signPdfResponse.setKey(factory.createSignPdfResponseKey(this.key));

	}
}
