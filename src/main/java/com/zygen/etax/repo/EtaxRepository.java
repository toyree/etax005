package com.zygen.etax.repo;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

import com.zygen.etax.model.ObjectFactory;
import com.zygen.etax.model.SignXmlModel;
import com.zygen.etax.model.SignXmlResponse;
import com.zygen.etax.xades.XadesBesSign;
import com.zygen.etax.xades.XadesProperties;

@Component
@EnableConfigurationProperties({XadesProperties.class})
public class EtaxRepository {

	private static final Logger log = LoggerFactory.getLogger(EtaxRepository.class);
	private SignXmlResponse response;
	private ObjectFactory factory;
	private final XadesProperties xadesProperties;

	@PostConstruct
	public void initData() {
		log.info("EtaxRepo initData Process");
		factory = new ObjectFactory();
		response = factory.createSignXmlResponse();
	}
	
	public EtaxRepository(XadesProperties xadesProperties) {
		this.xadesProperties = xadesProperties;
	}
	
	public SignXmlResponse getResponse() {
		return response;
	}

	public void setResponse(SignXmlResponse response) {
		this.response = response;
	}

	public void callAgent(String signingConfigName, String xmlContent) {
		
		log.info(xadesProperties.toString());
		response = new SignXmlResponse();
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

		response.setSignXmlResult(factory.createSignXmlModel(signXmlModel));

	}

}
