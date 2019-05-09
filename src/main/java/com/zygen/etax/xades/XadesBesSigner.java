package com.zygen.etax.xades;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.GregorianCalendar;

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

import org.apache.commons.io.FilenameUtils;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.pdfbox.pdmodel.PDDocumentNameDictionary;
import org.apache.pdfbox.pdmodel.PDEmbeddedFilesNameTreeNode;
import org.apache.pdfbox.pdmodel.common.PDMetadata;
import org.apache.pdfbox.pdmodel.common.filespecification.PDComplexFileSpecification;
import org.apache.pdfbox.pdmodel.common.filespecification.PDEmbeddedFile;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.pdfbox.pdmodel.graphics.color.PDOutputIntent;
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

	private static final Logger log = LoggerFactory.getLogger(XadesBesSign.class);
	private static float pdfVer = 1.7f;
	XadesSigner signer;
	private String key;
	private String tempPath;
	private XadesProperties properties;

	public XadesBesSigner(String tempPath) {
		this.tempPath = tempPath;
	}

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
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

	public void setProperties(XadesProperties properties) {
		this.properties = properties;
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
	public String signWithoutIDEnveloped(InputStream input) throws IllegalArgumentException, SAXException, IOException,
			ParserConfigurationException, XAdES4jException, Exception {

		String refUri;
		String signedXml = new String();
		String buffer = new String();
		String line = new String();
		FileOutputStream outputStream = new FileOutputStream(tempPath);
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
			XadesSignatureResult result = signer.sign(new SignedDataObjects(dataObjRef),
					sourceDoc.getDocumentElement());
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
			InputStream signedXmlInputStream = new FileInputStream(tempPath);
			BufferedReader reader = new BufferedReader(
					new InputStreamReader(signedXmlInputStream, StandardCharsets.UTF_8));
			line = reader.readLine();
			while (line != null) {
				buffer += line;
				line = reader.readLine();
			}
			signedXml = buffer;
			signedXmlInputStream.close();
			deleteTempFile(tempPath);
		} catch (Exception e) {
			log.error(e.getMessage());
		}
		return signedXml;
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

	public String convertPDFtoA3(String pdfPath, String xmlPath, String colorProfile) {
		log.info("Convert PDF to A3");
		String signedPdf = new String();
		File pdfFile = new File(pdfPath);
		PDDocument doc = loadPDF(pdfFile);
		try {
			File colorFile = new File(colorProfile);
			InputStream colorIS = new FileInputStream(colorFile);
			PDDocumentCatalog cat = makeA3compliant(doc, key + "_callpdf.xml");
			log.info("Get Doc Cat Success");
			attachFile(doc, xmlPath);
			addOutputIntent(doc, cat, colorIS);
			OutputStream pdfOutput = new FileOutputStream(properties.getTemp_file_path()+key+"signed_callpdf.pdf");
			doc.setVersion(pdfVer);
			doc.save(pdfOutput);
			doc.close();
			pdfOutput.close();
		} catch (Exception e) {
			log.error(e.getMessage());
		}
		return signedPdf;
	}

	private PDDocument loadPDF(File file) {
		log.info("Loading PDF from path : " + file.getPath());
		PDDocument doc = null;
		try {
			doc = PDDocument.load(file);
			log.info("Loading file success");
		} catch (InvalidPasswordException e) {
			log.error(e.getMessage());
		} catch (IOException e) {
			log.error(e.getMessage());
		}
		return doc;
	}

	private PDDocumentCatalog makeA3compliant(PDDocument doc, String xmlFileName) throws Exception {
		log.info("makeA3compliant");
		PDDocumentCatalog cat = doc.getDocumentCatalog();
		PDDocumentInformation pdd = doc.getDocumentInformation();
		PDMetadata metadata = new PDMetadata(doc);
		cat.setMetadata(metadata);
		PDDocumentInformation pdi = new PDDocumentInformation();
		pdi.setProducer(pdd.getProducer());
		pdi.setAuthor(pdd.getAuthor());
		pdi.setTitle(pdd.getTitle());
		pdi.setSubject(pdd.getSubject());
		pdi.setKeywords(pdd.getKeywords());
		// Set OID
		// pdi.setCustomMetadataValue("OID", "10.2.3.65.5");
		doc.setDocumentInformation(pdi);
		// use for eTax invoice only
		Charset charset = StandardCharsets.UTF_8;
		byte[] fileBytes = Files.readAllBytes(new File(properties.getXmpTemplatePath()).toPath());
		String content = new String(fileBytes, charset);
		content = content.replaceAll("@DocumentFileName", xmlFileName);
		content = content.replaceAll("@DocumentType", properties.getDocType());
		content = content.replaceAll("@DocumentVersion", properties.getDocVersion());
		log.info(content);
		byte[] editedBytes = content.getBytes(charset);
		metadata.importXMPMetadata(editedBytes);
		return cat;
	}

	private void attachFile(PDDocument doc, String xmlFilePath) throws IOException {
		log.info("AttachFile");
		PDEmbeddedFilesNameTreeNode efTree = new PDEmbeddedFilesNameTreeNode();
		File embedFile = new File(xmlFilePath);
		String subType = FilenameUtils.getExtension(xmlFilePath);
		String embedFileName = FilenameUtils.getName(xmlFilePath);
		// first create the file specification, which holds the embedded file

		PDComplexFileSpecification fs = new PDComplexFileSpecification();
		fs.setFile(embedFileName);
		COSDictionary dict = fs.getCOSObject();
		// Relation "Source" for linking with eg. catalog
		dict.setName("AFRelationship", "Source");

		dict.setString("UF", embedFileName);

		InputStream is = new FileInputStream(embedFile);

		PDEmbeddedFile ef = new PDEmbeddedFile(doc, is);

		// set some of the attributes of the embedded file
		ef.setModDate(GregorianCalendar.getInstance());

		ef.setSize((int) embedFile.length());
		ef.setCreationDate(new GregorianCalendar());
		fs.setEmbeddedFile(ef);
		ef.setSubtype(subType);

		// now add the entry to the embedded file tree and set in the document.
		efTree.setNames(Collections.singletonMap(embedFileName, fs));

		// attachments are stored as part of the "names" dictionary in the
		PDDocumentCatalog catalog = doc.getDocumentCatalog();

		PDDocumentNameDictionary names = new PDDocumentNameDictionary(doc.getDocumentCatalog());
		names.setEmbeddedFiles(efTree);
		catalog.setNames(names);

		COSDictionary dict2 = catalog.getCOSObject();
		COSArray array = new COSArray();
		array.add(fs.getCOSObject());
		dict2.setItem("AF", array);

	}

	private void addOutputIntent(PDDocument doc, PDDocumentCatalog cat, InputStream colorProfile) throws IOException {
		log.info("AddOutputIntent");
		if (cat.getOutputIntents().isEmpty()) {
			PDOutputIntent oi = new PDOutputIntent(doc, colorProfile);
			oi.setInfo("sRGB IEC61966-2.1");
			oi.setOutputCondition("sRGB IEC61966-2.1");
			oi.setOutputConditionIdentifier("sRGB IEC61966-2.1");
			oi.setRegistryName("http://www.color.org");
			cat.addOutputIntent(oi);
		}

	}

}
