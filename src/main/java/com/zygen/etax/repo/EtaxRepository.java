package com.zygen.etax.repo;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.annotation.PostConstruct;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;

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
		
		etaxToken.reconnect();

		log.info("Request Key : " + key + " CallAgentGetXml");
		signXmlResponse = factory.createSignXmlResponse();
		try {
			EtaxSigner etaxSigner = new EtaxSigner();
			setInitialEtaxSigner(etaxSigner);
			xmlContent = StringEscapeUtils.unescapeHtml4(xmlContent);
			InputStream inputXmlContent = new ByteArrayInputStream(xmlContent.getBytes(StandardCharsets.UTF_8));
//			login();
			signXmlResponse.setSignXmlResult(factory.createSignXmlRequestXmlContent((StringEscapeUtils.escapeXml10(
					etaxSigner.signXML(inputXmlContent, etaxProperties.getTemp_file_path() + key + "_signed.xml")
							.toString()))));
//			logout();
		} catch (Exception e) {
			log.error(e.getMessage());
		}
		signXmlResponse.setKey(factory.createSignXmlResponseKey(key));
	}

	public void callAgentGetPdf(String pdfContent) {
		etaxToken.reconnect();
		log.info("callAgentGetPdf");
		signPdfResponse = factory.createSignPdfResponse();
		String pdfPath = etaxProperties.getTemp_file_path() + key + "_pd.pdf";
		String signedPdfPath = etaxProperties.getTemp_file_path() + key + "_signedpd.pdf";
		try {
			byte[] pdfByte = Base64.getDecoder().decode(pdfContent.getBytes());
			InputStream isPdfContent = new ByteArrayInputStream(pdfByte);
			EtaxFileService.createTempFile(pdfPath, isPdfContent);
			EtaxSigner etaxSigner = new EtaxSigner();
			setInitialEtaxSigner(etaxSigner);
//			login();
			signPdfResponse.setSignPdfResult(
					factory.createSignPdfResponseSignPdfResult(etaxSigner.signPDF(pdfPath, signedPdfPath).toString()));
//			logout();
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

	private void setInitialEtaxSigner(EtaxSigner etaxSigner) {
		etaxSigner.setPrivateKey(etaxToken.getPrivateKey());
		etaxSigner.setCertificate(etaxToken.getCertificate());
		etaxSigner.setCertificateChain(etaxToken.getCertificateChain());
		etaxSigner.setKeyStore(etaxToken.getKeyStore());
		etaxSigner.setProvidername(etaxToken.getProviderName());
		etaxSigner.setX509Certificate(etaxToken.getX509Certificate());
		etaxSigner.setKeyStorePrivateKeyEntry(etaxToken.getKeyStorePrivateKeyEntry());
	}
	
	private void login() throws LoginException {
//		etaxToken.getAuthProvider().login(new Subject(), new PasswordCallBackHandler());
//		log.info(etaxToken.getAuthProvider().getName() + " Login success!!");
	}
	
	private void logout() throws LoginException {
//		etaxToken.getAuthProvider().logout();
//		log.info(etaxToken.getAuthProvider().getName() + " Logout success!!");
	}
	
//	public class PasswordCallBackHandler implements CallbackHandler {
//
//		@Override
//		public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
//			if (!(callbacks[0] instanceof PasswordCallback)) {
//				throw new UnsupportedCallbackException(callbacks[0]);
//			}
//			PasswordCallback pc = (PasswordCallback) callbacks[0];
//			pc.setPassword(etaxProperties.getCs11_password().toCharArray());
//		}
//
//	}
}
