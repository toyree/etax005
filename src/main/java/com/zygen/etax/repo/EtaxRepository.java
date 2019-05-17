package com.zygen.etax.repo;

import java.io.ByteArrayInputStream;
import java.io.IOException;
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
import com.zygen.etax.util.EtaxToken;

@Component
public class EtaxRepository {

	private static final Logger log = LoggerFactory.getLogger(EtaxRepository.class);
	@Autowired
	private EtaxProperties etaxProperties;
	@Autowired
	private EtaxToken etaxToken;
	private SignXmlResponse signXmlResponse;
	private SignPdfResponse signPdfResponse;
	private ObjectFactory factory;
	private String key;

	@PostConstruct
	public void init() {
		log.info("EtaxRepository Initiated");
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
			etaxSigner.setXadesSigner(etaxToken.getXadesSigner());
			xmlContent = StringEscapeUtils.unescapeHtml4(xmlContent);
			InputStream inputXmlContent = new ByteArrayInputStream(xmlContent.getBytes(StandardCharsets.UTF_8));
			signXmlResponse.setSignXmlResult(factory.createSignXmlRequestXmlContent((StringEscapeUtils.escapeXml10(
					etaxSigner.signXML(inputXmlContent, etaxProperties.getTemp_file_path() + key + "_signed.xml")
							.toString()))));
		} catch (Exception e) {
			log.error(e.getMessage());
		}
		signXmlResponse.setKey(factory.createSignXmlResponseKey(key));
	}

	public void callAgentGetPdf(String pdfContent) {
		log.info("callAgentGetPdf");
		signPdfResponse = factory.createSignPdfResponse();
		String pdfPath = etaxProperties.getTemp_file_path() + key + "_pd.pdf";
		String signedPdfPath = etaxProperties.getTemp_file_path() + key + "_signedpd.pdf";
		try {
			
			byte[] pdfByte = Base64.getDecoder().decode(pdfContent);
			InputStream isPdfContent = new ByteArrayInputStream(pdfByte);
			EtaxFileService.createTempFile(pdfPath, isPdfContent);
			EtaxSigner etaxSigner = new EtaxSigner();
			etaxSigner.setPrivateKey(etaxToken.getPrivateKey());
			etaxSigner.setCertificate(etaxToken.getCertificate());
			etaxSigner.setCertificateChain(etaxToken.getCertificateChain());
			etaxSigner.setKeyStore(etaxToken.getKeyStore());
			signPdfResponse.setSignPdfResult(
					factory.createSignPdfResponseSignPdfResult(etaxSigner.signPDF(pdfPath, signedPdfPath).toString()));
		} catch (Exception e) {
			log.error(e.getMessage());
		}
		try {
			EtaxFileService.deleteTempFile(pdfPath);
		} catch (IOException e) {
			log.error(e.getMessage());
		}
		signPdfResponse.setKey(factory.createSignPdfResponseKey(this.key));

	}
}
