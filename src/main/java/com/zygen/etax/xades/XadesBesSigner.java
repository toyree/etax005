package com.zygen.etax.xades;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import xades4j.UnsupportedAlgorithmException;
import xades4j.XAdES4jException;
import xades4j.algorithms.Algorithm;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.algorithms.GenericAlgorithm;
import xades4j.production.DataObjectReference;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSignatureResult;
import xades4j.production.XadesSigner;
import xades4j.production.XadesSigningProfile;
import xades4j.properties.DataObjectDesc;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SigningCertChainException;
import xades4j.providers.impl.DefaultAlgorithmsProviderEx;
import xades4j.providers.impl.DirectPasswordProvider;
import xades4j.providers.impl.FileSystemKeyStoreKeyingDataProvider;
import xades4j.providers.impl.FirstCertificateSelector;
import xades4j.providers.impl.PKCS11KeyStoreKeyingDataProvider;
import xades4j.verification.UnexpectedJCAException;

public class XadesBesSigner {

//	private static final String outputTempFile = "temp/tempSigned.xml";
	private static final Logger log = LoggerFactory.getLogger(XadesBesSign.class);
	XadesSigner signer;
	private String tempPath;
	
	public XadesBesSigner(String tempPath) {
		this.tempPath = tempPath;
	}

	public void setSignerPkcs11(String libPath, String providerName, int slotId, String password) throws Exception {// SigningException
		// {
		log.info("SetSignerPkcs11");
		try {
			AlgorithmsProviderEx ap = new DefaultAlgorithmsProviderEx() {

				@Override
				public String getDigestAlgorithmForDataObjsReferences() {
					return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
				}

				@Override
				public String getDigestAlgorithmForReferenceProperties() {
					return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
				}

				@Override
				public Algorithm getSignatureAlgorithm(String keyAlgorithmName) throws UnsupportedAlgorithmException {
					return new GenericAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512);
				}
			};

			KeyingDataProvider keyingProvider = getKeyingDataProvider(libPath, providerName, slotId, password);
			XadesSigningProfile p = new XadesBesSigningProfile(keyingProvider);
			p.withAlgorithmsProviderEx(ap);

			signer = p.newSigner();
		} catch (Exception ex) {
			throw new Exception("Error " + ex);
		}
	}

	public void setSignerPkcs12(String keyPath, String password, String pkType) throws Exception {// SigningException
		log.info("SetSignerPkcs12");
		try {
			AlgorithmsProviderEx ap = new DefaultAlgorithmsProviderEx() {

				@Override
				public String getDigestAlgorithmForDataObjsReferences() {
					return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
				}

				@Override
				public String getDigestAlgorithmForReferenceProperties() {
					return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
				}

				@Override
				public Algorithm getSignatureAlgorithm(String keyAlgorithmName) throws UnsupportedAlgorithmException {
					return new GenericAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512);
				}
			};
			KeyingDataProvider keyingProvider = getKeyingDataProvider(keyPath, password, pkType);
			XadesSigningProfile p = new XadesBesSigningProfile(keyingProvider);
			p.withAlgorithmsProviderEx(ap);

			signer = p.newSigner();
		} catch (Exception ex) {
			throw new Exception("Error " + ex);
		}
	}

	private KeyingDataProvider getKeyingDataProvider(String libPath, String providerName, int slotId, String password)
			throws KeyStoreException, SigningCertChainException, UnexpectedJCAException, NoSuchAlgorithmException,
			CertificateException, IOException, UnrecoverableKeyException {
		log.info("getKeyingDataProvider");
		KeyingDataProvider keyingProvider = new PKCS11KeyStoreKeyingDataProvider(libPath, providerName, slotId,
				new FirstCertificateSelector(), new DirectPasswordProvider(password), null, false);

		return keyingProvider;
	}

	private KeyingDataProvider getKeyingDataProvider(String keyPath, String password, String pkType)
			throws KeyStoreException, SigningCertChainException, UnexpectedJCAException {
		// P12
		log.info("getKeyingDataProvider");
		KeyingDataProvider keyingProvider = new FileSystemKeyStoreKeyingDataProvider(pkType, keyPath,
				new FirstCertificateSelector(), new DirectPasswordProvider(password),
				new DirectPasswordProvider(password), false);

		if (keyingProvider.getSigningCertificateChain().isEmpty()) {
			throw new IllegalArgumentException("Cannot initialize keystore with path " + keyPath);
		}
		return keyingProvider;
	}

	/**
	 * Generate the signature and output a single signed file using the enveloped
	 * structure This means that the signature is within the signed XML This method
	 * signs the root node, not an ID
	 * 
	 * @param inputPath
	 * @param outputPath
	 * @throws ParserConfigurationException
	 * @throws SAXException
	 * @throws TransformerFactoryConfigurationError
	 * @throws XAdES4jException
	 * @throws TransformerConfigurationException
	 * @throws TransformerException
	 * @throws IOException
	 * @throws FileNotFoundException
	 */
	public String signWithoutIDEnveloped(InputStream input)
			throws IllegalArgumentException, SAXException, IOException, ParserConfigurationException, XAdES4jException, Exception{

		String refUri;
		String signedXml = new String();
		String buffer    = new String();
		String line		 = new String();
		log.info("signWithoutIDEnveloped");
		FileOutputStream outputStream = new FileOutputStream(tempPath);
		log.info("Temp file was created file " + tempPath);
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			Document sourceDoc = dbf.newDocumentBuilder().parse(input);
			Element elementToSign = sourceDoc.getDocumentElement();
			if (elementToSign.hasAttribute("Id")) {
				refUri = '#' + elementToSign.getAttribute("Id");
			} else {
				if (elementToSign.getParentNode().getNodeType() != Node.DOCUMENT_NODE) {
					outputStream.close();
					deleteTempFile(tempPath);
					throw new IllegalArgumentException("Element without Id must be the document root");
				}
				refUri = "";
			}
			DataObjectDesc dataObjRef = new DataObjectReference(refUri)
					.withTransform(new EnvelopedSignatureTransform());
			XadesSignatureResult result =  signer.sign(new SignedDataObjects(dataObjRef), sourceDoc.getDocumentElement());
			XMLSignature signature = result.getSignature();
			Document docs = signature.getDocument();
			DOMSource docSource = new DOMSource(docs);
			Transformer transformer = TransformerFactory.newInstance().newTransformer();
			transformer.setOutputProperty(OutputKeys.METHOD, "xml");
			transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
			transformer.setOutputProperty(OutputKeys.STANDALONE, "yes");
			StreamResult streamResult = new StreamResult(new OutputStreamWriter(outputStream, StandardCharsets.UTF_8));
			transformer.transform(docSource, streamResult);
			outputStream.close();
			log.info("Get Signed XML and Convert To String");
			InputStream signedXmlInputStream = new FileInputStream(tempPath);
			BufferedReader reader = new BufferedReader(new InputStreamReader(signedXmlInputStream,StandardCharsets.UTF_8));
			line = reader.readLine();
			while(line != null) {
				buffer += line;	
				line = reader.readLine();
			}
			signedXml = buffer;
			signedXmlInputStream.close();
			deleteTempFile(tempPath);
		} catch (Exception e) {
			throw e;
		}
		return signedXml;
	}

	public XadesBesSigner() {
		signer = null;
	}

	public String getTempPath() {
		return tempPath;
	}

	public void setTempPath(String tempPath) {
		this.tempPath = tempPath;
	}

	private void deleteTempFile(String tempPath) {
		File file = new File(tempPath);
		if (file.exists()) {
			if (file.delete()) {
				log.info(tempPath + " Delete Completed");
			}
		} else {
			log.info(tempPath + " File doesn't exist");
		}
	}

}
