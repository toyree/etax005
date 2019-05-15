package com.zygen.etax.xades;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.zygen.etax.sats.SignAndTimeStamp;

public class XadesBesSign {

	private static final Logger log = LoggerFactory.getLogger(XadesBesSign.class);
	private XadesProperties properties;
	private String key;

	public XadesBesSign(XadesProperties properties) {
		this.properties = properties;
	}

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public void checkPK(XadesBesSigner signer) throws Exception {
		log.info("Check PK");
		if (properties.getType().equals("PKCS11")) {
			signer.setSignerPkcs11(properties.getCs11_lib_path(), properties.getCs11_provider_name(),
					Integer.parseInt(properties.getCs11_slot_id()), properties.getCs11_password());
		} else if (properties.getType().equals("PKCS12")) {
			signer.setSignerPkcs12(properties.getCs12_path(), properties.getCs12_password(), properties.getType());
		} else {
			throw new Exception("Please Check application.properties : pk.type");
		}
	}

	public String signXML(InputStream inputXml) throws Exception {
		log.info("Request Key : " + key + " signXML");
		XadesBesSigner signer = new XadesBesSigner(properties.getTemp_file_path() + key + "_callxml.xml");
		checkPK(signer);
		signer.setKey(key);
		signer.setProperties(properties);
		String outputXml = new String();
		try {
			outputXml = signer.signWithoutIDEnveloped(inputXml);
		} catch (Exception e) {
			throw e;
		}
		return outputXml;
	}

	public String signPdf(InputStream pdfInputStream) throws Exception {
		log.info("Request Key : " + key + " signPdf");
		XadesBesSigner signer = new XadesBesSigner();
		checkPK(signer);
		signer.setKey(key);
		signer.setProperties(properties);
		String outputPdf = new String();
		String pdfPath = properties.getTemp_file_path() + key + "_callpdf.pdf";
		String signedPdfPath = properties.getTemp_file_path() + key + "_signedcallpdf.pdf";
		createTempFile(pdfPath, pdfInputStream);
//		outputPdf = signer.convertPDFtoA3(pdfPath, properties.getColorProfile());
		SignAndTimeStamp sats = new SignAndTimeStamp();
		sats.setProperties(properties);
		outputPdf = sats.signWithTSA(properties.getCs12_password(), properties.getCs12_path() , pdfPath, signedPdfPath, null, properties.getCert_store_dir(), properties.getCert_store_dir(), properties.getType());
		XadesBesSigner.deleteTempFile(pdfPath);
		XadesBesSigner.deleteTempFile(signedPdfPath);
		return outputPdf;
	}

	private void createTempFile(String path, InputStream inputStream) {
		log.info("Create temp file path : " + path);
		try {
			byte[] buffer = new byte[inputStream.available()];
			inputStream.read(buffer);
			OutputStream outputStream = new FileOutputStream(path);
			outputStream.write(buffer);
			outputStream.close();
			inputStream.close();
		} catch (IOException e) {
			log.error(e.getMessage());
		}

	}

}
